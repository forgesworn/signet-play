//! Contacts from My Signet's contacts-v2 app grant: pairing (ack wait +
//! verification code), the stored grant, projection fetch / accept, and the
//! game's contact model.
//!
//! The grant / snapshot types, the ack-candidate gates and projection accept
//! rules are adapted from the `store`, `ack_wait`, `sync` and `pairing_flow`
//! modules of an earlier game codebase (see `NOTICE`), retargeted onto this
//! crate's relay trait.
//! Fail-closed rule kept: a stale snapshot (past `expiresAt`) admits nobody by
//! tier, but its blocks still apply.
//!
//! The projection carries no owner key, and the person picks the directory on
//! My Signet's approval screen independently of the persona picked at
//! sign-in. The game therefore binds the stored grant to the persona that was
//! signed in when it was paired ([`Grant::persona`]) and drops it when another
//! persona (or nobody) is signed in, so one persona's book never decides for
//! another on a shared device.

use std::collections::HashSet;
use std::time::Duration;

use nostr::{Event, EventId, Filter, Keys, Kind, PublicKey, ToBech32};
use serde::{Deserialize, Serialize};

use crate::contacts_wire::constants::{ACK_ATTEMPT_CAP, ACK_CANDIDATE_LIMIT, ACK_KIND, ACK_STORED_KIND, PROJECTION_KIND};
use crate::contacts_wire::pairing::is_valid_contacts_relay_url;
use crate::contacts_wire::{
    self as wire, Ack, Capability, Directory, Projection, ack_event_is_fresh, ack_tag, decrypt_ack_event, is_newer,
    open_vault_envelope_text, parse_projection, projection_tag,
};
use crate::relay::{RelayMsg, Subscription};

/// What the game asks for: names, tiers and blocks. Nothing else.
pub const REQUESTED_CAPABILITIES: [Capability; 3] =
    [Capability::ReadDirectory, Capability::ReadTier, Capability::BlocksRead];

/// The My Signet deployment the web / App Link carriers point at.
pub const MYSIGNET_HOST: &str = "mysignet.app";

pub const GRANT_VERSION: u32 = 1;
pub const SNAPSHOT_VERSION: u32 = 1;

// ─── Stored grant + snapshot ────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub v: u32,
    pub app_secret_hex: String,
    pub grant_id: String,
    pub rail_pubkey: String,
    pub projection_tag: String,
    pub relay: String,
    pub granted_capabilities: Vec<Capability>,
    pub max_staleness_seconds: u64,
    pub paired_at: u64,
    /// The persona (hex) signed in when this grant was paired. A grant bound
    /// to another persona, or to none (older files), is not used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona: Option<String>,
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("app_secret_hex", &"<redacted>")
            .field("grant_id", &self.grant_id)
            .field("rail_pubkey", &self.rail_pubkey)
            .field("relay", &self.relay)
            .field("granted_capabilities", &self.granted_capabilities)
            .field("persona", &self.persona)
            .finish()
    }
}

impl Grant {
    pub fn from_ack(ack: &Ack, app_keys: &Keys, now: u64) -> Self {
        Self {
            v: GRANT_VERSION,
            app_secret_hex: app_keys.secret_key().to_secret_hex(),
            grant_id: ack.grant_id.clone(),
            rail_pubkey: ack.rail_pubkey.clone(),
            projection_tag: ack.projection_tag.clone(),
            relay: ack.relay.clone(),
            granted_capabilities: ack.granted_capabilities.clone(),
            max_staleness_seconds: ack.max_staleness_seconds,
            paired_at: now,
            persona: None,
        }
    }

    /// Whether this grant was paired by `persona`.
    pub fn is_for(&self, persona: &PublicKey) -> bool {
        self.persona.as_deref() == Some(persona.to_hex().as_str())
    }

    pub fn app_keys(&self) -> Option<Keys> {
        nostr::SecretKey::from_hex(&self.app_secret_hex).ok().map(Keys::new)
    }

    pub fn is_well_formed(&self) -> bool {
        let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        self.v >= 1
            && self.app_keys().is_some()
            && hex(&self.grant_id, 32)
            && hex(&self.rail_pubkey, 64)
            && is_valid_contacts_relay_url(&self.relay)
            && !self.granted_capabilities.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub v: u32,
    pub projection: Projection,
    pub fetched_at: u64,
}

// ─── Pairing ────────────────────────────────────────────────────────────────

/// A fresh 32-hex-char challenge.
pub fn fresh_challenge() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS random source");
    hex::encode(b)
}

/// The three ways to hand a pairing request to My Signet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingLinks {
    /// `signet-grant://pair?…` (QR for a second device).
    pub uri: String,
    /// `https://mysignet.app/?pair=1&…` (web My Signet; desktop).
    pub web: String,
    /// `https://mysignet.app/pair?…` (verified App Link: opens the Android app).
    pub app_link: String,
}

pub fn pairing_links(app: &PublicKey, app_name: &str, relay: &str, now: u64, challenge: &str) -> Result<PairingLinks, String> {
    let uri = wire::build_pairing_uri(
        &app.to_hex(),
        app_name,
        &REQUESTED_CAPABILITIES,
        Directory::Owner,
        relay,
        now,
        challenge,
    )
    .map_err(|e| format!("could not build the pairing request: {e:?}"))?;
    let query = uri.split_once('?').map_or("", |(_, q)| q).to_string();
    Ok(PairingLinks {
        web: wire::web_carrier(MYSIGNET_HOST, &uri),
        app_link: format!("https://{MYSIGNET_HOST}/pair?{query}"),
        uri,
    })
}

/// The filters an ack arrives on: the ephemeral kind 21237 to the app key,
/// and its stored kind 30078 copy under `ack_tag(challenge)`.
pub fn ack_filters(app: &PublicKey, challenge: &str) -> Vec<Filter> {
    vec![
        Filter::new().kind(Kind::Custom(ACK_KIND)).pubkey(*app).limit(ACK_CANDIDATE_LIMIT),
        Filter::new()
            .kind(Kind::Custom(ACK_STORED_KIND))
            .identifier(ack_tag(challenge))
            .limit(ACK_CANDIDATE_LIMIT),
    ]
}

#[derive(Debug, PartialEq, Eq)]
pub enum AckWait {
    Found(Ack),
    /// No valid ack in time, or the attempt cap was hit (flooded).
    TimedOut,
}

/// What the next ack candidate on a pairing subscription turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum AckNext {
    /// Fresh, decrypts to our challenge, grants nothing we did not ask for.
    Ack(Ack),
    /// The attempt cap was hit (flooded): fail closed.
    Capped,
    /// The subscription ended.
    Closed,
}

/// Read candidates from an open ack subscription until one is a valid ack.
/// `attempted` carries the per-pairing attempt count across calls.
pub async fn next_ack(sub: &mut Subscription, app_keys: &Keys, challenge: &str, attempted: &mut HashSet<EventId>) -> AckNext {
    loop {
        match sub.recv().await {
            Some(RelayMsg::Event(ev)) => {
                if let Some(next) = consider_ack(&ev, app_keys, challenge, attempted) {
                    return next;
                }
            }
            Some(RelayMsg::Eose) => {}
            None => return AckNext::Closed,
        }
    }
}

/// One candidate: `Some(Ack | Capped)` when it decides something, `None` to keep reading.
pub fn consider_ack(ev: &Event, app_keys: &Keys, challenge: &str, attempted: &mut HashSet<EventId>) -> Option<AckNext> {
    if attempted.len() >= ACK_ATTEMPT_CAP {
        return Some(AckNext::Capped);
    }
    if !ack_event_is_fresh(ev.created_at.as_secs(), crate::unix_now()) || !attempted.insert(ev.id) {
        return None;
    }
    decrypt_ack_event(ev, app_keys, challenge, &REQUESTED_CAPABILITIES).map(AckNext::Ack)
}

/// Two acks name the same grant (the ephemeral ack and its stored copy do).
pub fn same_grant(a: &Ack, b: &Ack) -> bool {
    a.grant_id == b.grant_id && a.rail_pubkey == b.rail_pubkey
}

/// Wait on an open ack subscription for the first candidate that is fresh,
/// decrypts to our challenge, and grants nothing we did not ask for.
pub async fn await_ack(mut sub: Subscription, app_keys: &Keys, challenge: &str, timeout: Duration) -> AckWait {
    let mut attempted: HashSet<EventId> = HashSet::new();
    let wait = async {
        match next_ack(&mut sub, app_keys, challenge, &mut attempted).await {
            AckNext::Ack(a) => AckWait::Found(a),
            AckNext::Capped | AckNext::Closed => AckWait::TimedOut,
        }
    };
    tokio::time::timeout(timeout, wait).await.unwrap_or(AckWait::TimedOut)
}

/// The code the person types into My Signet, formatted `123 456`.
pub fn verification_code(app: &PublicKey, challenge: &str, ack: &Ack) -> Option<String> {
    wire::pairing_code(&app.to_hex(), challenge, &ack.grant_id, &ack.rail_pubkey).map(|c| wire::format_pairing_code(&c))
}

// ─── Projection sync ────────────────────────────────────────────────────────

pub fn projection_filter(grant: &Grant) -> Option<Filter> {
    let rail = PublicKey::from_hex(&grant.rail_pubkey).ok()?;
    Some(
        Filter::new()
            .kind(Kind::Custom(PROJECTION_KIND))
            .author(rail)
            .identifier(projection_tag(&grant.grant_id))
            .limit(5),
    )
}

/// Open one projection event for `grant`: author, signature, `d`, vault
/// envelope, wire parse, scopes within the grant, `grantId` match.
pub fn open_projection(ev: &Event, grant: &Grant) -> Option<Projection> {
    if ev.kind != Kind::Custom(PROJECTION_KIND) || ev.pubkey.to_hex() != grant.rail_pubkey {
        return None;
    }
    if ev.verify().is_err() {
        return None;
    }
    if ev.tags.identifier() != Some(projection_tag(&grant.grant_id).as_str()) {
        return None;
    }
    let keys = grant.app_keys()?;
    let rail = PublicKey::from_hex(&grant.rail_pubkey).ok()?;
    let body = open_vault_envelope_text(&ev.content, keys.secret_key(), &rail)?;
    let p = parse_projection(&body, &grant.granted_capabilities, grant.max_staleness_seconds)?;
    (p.grant_id == grant.grant_id).then_some(p)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    Unchanged,
    Replace(Box<Projection>),
    Revoked,
}

pub fn accept_projection(events: &[Event], grant: &Grant, held: Option<&Projection>) -> Accepted {
    let mut best: Option<Projection> = None;
    for ev in events {
        let Some(p) = open_projection(ev, grant) else { continue };
        if p.revoked {
            return Accepted::Revoked;
        }
        if best.as_ref().is_none_or(|b| is_newer(&p, b)) {
            best = Some(p);
        }
    }
    match best {
        Some(p) if held.is_none_or(|h| is_newer(&p, h)) => Accepted::Replace(Box::new(p)),
        _ => Accepted::Unchanged,
    }
}

/// Outcome of one contacts refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactsSync {
    /// Nothing newer than what is held.
    Unchanged,
    /// A newer projection was accepted; `contacts` = visible count.
    Updated { contacts: usize },
    /// The owner revoked the grant in My Signet; grant and cache are deleted.
    Revoked,
}

// ─── The game's contact model ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Tier {
    Kin,
    Kith,
    Ken,
}

impl Tier {
    /// Kin and Kith may invite by default; Ken may not.
    pub fn may_invite(self) -> bool {
        matches!(self, Tier::Kin | Tier::Kith)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Grant-scoped opaque id from My Signet.
    pub id: String,
    /// The name the owner gave them in My Signet (or a short npub).
    pub display_name: String,
    /// Keys they may sign in with (persona or other identity keys).
    pub identities: Vec<PublicKey>,
    /// `None` = My Signet says "none", or the grant has no `read:tier`.
    pub tier: Option<Tier>,
    pub blocked: bool,
}

/// `npub1abcd…wxyz`.
pub fn short_npub(pk: &PublicKey) -> String {
    let n = pk.to_bech32().unwrap_or_default();
    if n.len() <= 16 { n } else { format!("{}…{}", &n[..9], &n[n.len() - 4..]) }
}

/// The contacts from the latest accepted projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactBook {
    contacts: Vec<Contact>,
    expires_at: u64,
    fetched_at: u64,
}

impl ContactBook {
    pub fn from_snapshot(s: &Snapshot) -> ContactBook {
        let contacts = s
            .projection
            .contacts
            .iter()
            .map(|c| {
                let identities: Vec<PublicKey> = c
                    .identities
                    .iter()
                    .flatten()
                    .filter_map(|i| PublicKey::from_hex(&i.pubkey).ok())
                    .collect();
                let tier = match c.effective_tier {
                    Some(wire::Tier::Kin) => Some(Tier::Kin),
                    Some(wire::Tier::Kith) => Some(Tier::Kith),
                    Some(wire::Tier::Ken) => Some(Tier::Ken),
                    Some(wire::Tier::None) | None => None,
                };
                // For display, also without what the hello's name sanitiser
                // drops (invisible and direction-changing characters); a name
                // of nothing else shows the short npub. Lookalikes stay alike:
                // "Mu\u{2060}m" shows as "Mum", as "Mum" does.
                let display_name = c
                    .display_name
                    .as_deref()
                    .map(|n| n.chars().filter(|ch| !crate::hidden_char(*ch)).collect::<String>())
                    .filter(|n| !n.trim().is_empty())
                    .or_else(|| identities.first().map(short_npub))
                    .unwrap_or_default();
                Contact { id: c.contact_id.clone(), display_name, identities, tier, blocked: c.blocked == Some(true) }
            })
            .collect();
        ContactBook { contacts, expires_at: s.projection.expires_at, fetched_at: s.fetched_at }
    }

    /// Every contact, blocked ones included.
    pub fn all(&self) -> &[Contact] {
        &self.contacts
    }

    /// What the contact picker shows: no blocked contacts and no contacts
    /// with no identity key; Kin, then Kith, then Ken, then untiered; by name.
    pub fn visible(&self) -> Vec<Contact> {
        let mut v: Vec<Contact> = self
            .contacts
            .iter()
            .filter(|c| !c.blocked && !c.identities.is_empty() && !self.is_blocked_any(&c.identities))
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            let rank = |t: Option<Tier>| t.map_or(3, |t| t as u8);
            rank(a.tier)
                .cmp(&rank(b.tier))
                .then_with(|| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()))
        });
        v
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn fetched_at(&self) -> u64 {
        self.fetched_at
    }

    /// Past the projection's `expiresAt`: tiers no longer admit anyone.
    pub fn is_stale(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Every key named by a blocked contact.
    pub fn blocked_keys(&self) -> Vec<PublicKey> {
        self.contacts.iter().filter(|c| c.blocked).flat_map(|c| c.identities.iter().copied()).collect()
    }

    /// Blocks always apply, stale or not, and beat every tier.
    pub fn is_blocked(&self, pk: &PublicKey) -> bool {
        self.contacts.iter().any(|c| c.blocked && c.identities.contains(pk))
    }

    fn is_blocked_any(&self, pks: &[PublicKey]) -> bool {
        pks.iter().any(|pk| self.is_blocked(pk))
    }

    /// Best tier among the (unblocked) contacts carrying `pk`; `None` when
    /// blocked, unknown, or the snapshot is stale.
    pub fn tier_of(&self, pk: &PublicKey, now: u64) -> Option<Tier> {
        if self.is_stale(now) || self.is_blocked(pk) {
            return None;
        }
        self.contacts.iter().filter(|c| c.identities.contains(pk)).filter_map(|c| c.tier).min()
    }

    /// The (unblocked) contact carrying `pk`, if any.
    pub fn find(&self, pk: &PublicKey) -> Option<&Contact> {
        self.contacts.iter().find(|c| !c.blocked && c.identities.contains(pk))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;
    use nostr::{EventBuilder, Tag, Timestamp};
    use serde_json::json;

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    /// A vault envelope (WIRE.md §5) sealed from `rail` to `app`, as My Signet makes it.
    pub(crate) fn seal(body: &str, rail: &Keys, app: &PublicKey) -> String {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        getrandom::fill(&mut key).unwrap();
        getrandom::fill(&mut iv).unwrap();
        let bucket = [4096usize, 8192, 16384, 32768, 65536].into_iter().find(|b| body.len() + 4 <= *b).unwrap();
        let mut padded = vec![0u8; bucket];
        padded[..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
        padded[4..4 + body.len()].copy_from_slice(body.as_bytes());
        let ct = Aes256Gcm::new_from_slice(&key).unwrap().encrypt(&Nonce::from(iv), padded.as_slice()).unwrap();
        let k = nostr::nips::nip44::encrypt(rail.secret_key(), app, B64.encode(key), nostr::nips::nip44::Version::V2).unwrap();
        json!({"v": 2, "k": k, "iv": B64.encode(iv), "ct": B64.encode(ct), "b": bucket}).to_string()
    }

    fn body(grant_id: &str, published_at: u64, expires_at: u64, revoked: bool, contacts: serde_json::Value) -> String {
        let mut b = json!({
            "v": 2, "grantId": grant_id,
            "scopes": ["signet.contacts.read:directory", "signet.contacts.read:tier", "signet.contacts.blocks.read"],
            "frontier": {"maxClock": published_at, "opCount": 1, "publishedAt": published_at, "deviceId": "2".repeat(32)},
            "issuedAt": published_at, "expiresAt": expires_at,
            "contacts": contacts,
        });
        if revoked {
            b["revoked"] = json!(true);
        }
        b.to_string()
    }

    struct World {
        rail: Keys,
        grant: Grant,
    }

    fn world() -> World {
        let app = Keys::generate();
        let rail = Keys::generate();
        let grant_id = "1".repeat(32);
        let grant = Grant {
            v: GRANT_VERSION,
            app_secret_hex: app.secret_key().to_secret_hex(),
            grant_id: grant_id.clone(),
            rail_pubkey: rail.public_key().to_hex(),
            projection_tag: projection_tag(&grant_id),
            relay: "wss://relay.example.com".into(),
            granted_capabilities: REQUESTED_CAPABILITIES.to_vec(),
            max_staleness_seconds: 21_600,
            paired_at: 1,
            persona: None,
        };
        World { rail, grant }
    }

    fn projection_event(w: &World, body: &str) -> Event {
        let app = w.grant.app_keys().unwrap().public_key();
        EventBuilder::new(Kind::Custom(PROJECTION_KIND), seal(body, &w.rail, &app))
            .tag(Tag::identifier(projection_tag(&w.grant.grant_id)))
            .custom_created_at(Timestamp::from(100))
            .sign_with_keys(&w.rail)
            .unwrap()
    }

    fn contacts_json(alex: &PublicKey, sam: &PublicKey, bo: &PublicKey) -> serde_json::Value {
        json!([
            {"contactId": "a".repeat(32), "identities": [{"pubkey": alex.to_hex()}], "displayName": "Alex", "effectiveTier": "kith"},
            {"contactId": "b".repeat(32), "identities": [{"pubkey": sam.to_hex()}], "displayName": "Sam", "effectiveTier": "kin"},
            {"contactId": "c".repeat(32), "identities": [{"pubkey": bo.to_hex()}], "displayName": "Bo", "effectiveTier": "kin", "blocked": true},
            {"contactId": "d".repeat(32), "identities": [{"pubkey": Keys::generate().public_key().to_hex()}], "displayName": "Ken Person", "effectiveTier": "ken"}
        ])
    }

    #[test]
    fn projection_decrypts_and_builds_the_book() {
        let w = world();
        let (alex, sam, bo) = (Keys::generate().public_key(), Keys::generate().public_key(), Keys::generate().public_key());
        let ev = projection_event(&w, &body(&w.grant.grant_id, 50, 10_000, false, contacts_json(&alex, &sam, &bo)));
        let Accepted::Replace(p) = accept_projection(&[ev], &w.grant, None) else { panic!("should accept") };
        let book = ContactBook::from_snapshot(&Snapshot { v: 1, projection: *p, fetched_at: 60 });
        let names: Vec<_> = book.visible().iter().map(|c| c.display_name.clone()).collect();
        assert_eq!(names, ["Sam", "Alex", "Ken Person"], "Kin, Kith, Ken; blocked hidden");
        assert!(book.is_blocked(&bo));
        assert_eq!(book.tier_of(&bo, 100), None);
        assert_eq!(book.tier_of(&sam, 100), Some(Tier::Kin));
        assert_eq!(book.tier_of(&alex, 100), Some(Tier::Kith));
        // Stale: tiers stop admitting, blocks still apply.
        assert_eq!(book.tier_of(&sam, 10_001), None);
        assert!(book.is_blocked(&bo));
    }

    /// Names show without the characters that draw nothing or reorder text,
    /// so two entries cannot look the same; a name of nothing else falls back
    /// to the short npub.
    #[test]
    fn contact_names_lose_invisible_characters() {
        let w = world();
        let (mum, blank) = (Keys::generate().public_key(), Keys::generate().public_key());
        let c = json!([
            {"contactId": "a".repeat(32), "identities": [{"pubkey": mum.to_hex()}], "displayName": "Mu\u{2060}m\u{061C}\u{FEFF}", "effectiveTier": "kin"},
            {"contactId": "b".repeat(32), "identities": [{"pubkey": blank.to_hex()}], "displayName": "\u{2061}\u{2064}", "effectiveTier": "kin"}
        ]);
        let ev = projection_event(&w, &body(&w.grant.grant_id, 50, 10_000, false, c));
        let Accepted::Replace(p) = accept_projection(&[ev], &w.grant, None) else { panic!("should accept") };
        let book = ContactBook::from_snapshot(&Snapshot { v: 1, projection: *p, fetched_at: 60 });
        assert_eq!(book.find(&mum).unwrap().display_name, "Mum");
        assert_eq!(book.find(&blank).unwrap().display_name, short_npub(&blank));
    }

    #[test]
    fn projection_for_another_grant_or_author_is_ignored() {
        let w = world();
        let c = json!([]);
        let wrong_grant = projection_event(&w, &body(&"9".repeat(32), 50, 10_000, false, c.clone()));
        assert_eq!(accept_projection(&[wrong_grant], &w.grant, None), Accepted::Unchanged);
        let impostor = Keys::generate();
        let app = w.grant.app_keys().unwrap().public_key();
        let forged = EventBuilder::new(
            Kind::Custom(PROJECTION_KIND),
            seal(&body(&w.grant.grant_id, 50, 10_000, false, c), &impostor, &app),
        )
        .tag(Tag::identifier(projection_tag(&w.grant.grant_id)))
        .sign_with_keys(&impostor)
        .unwrap();
        assert_eq!(accept_projection(&[forged], &w.grant, None), Accepted::Unchanged);
    }

    #[test]
    fn newer_wins_and_revocation_is_reported() {
        let w = world();
        let old = projection_event(&w, &body(&w.grant.grant_id, 50, 10_000, false, json!([])));
        let new = projection_event(&w, &body(&w.grant.grant_id, 70, 10_000, false, json!([])));
        let Accepted::Replace(p) = accept_projection(&[old.clone(), new], &w.grant, None) else { panic!() };
        assert_eq!(p.frontier.published_at, 70);
        assert_eq!(accept_projection(&[old], &w.grant, Some(&p)), Accepted::Unchanged);
        let rev = projection_event(&w, &body(&w.grant.grant_id, 80, 10_000, true, json!([])));
        assert_eq!(accept_projection(&[rev], &w.grant, Some(&p)), Accepted::Revoked);
    }

    #[test]
    fn pairing_links_are_owner_only_with_three_caps() {
        let app = Keys::generate().public_key();
        let l = pairing_links(&app, "Twang Thang", "wss://relay.damus.io", 1000, &fresh_challenge()).unwrap();
        assert!(l.uri.starts_with("signet-grant://pair?v=2&app="));
        assert!(l.uri.contains("&name=Twang+Thang&"));
        assert!(l.uri.contains("&dir=owner&"));
        assert!(l.uri.contains(
            "caps=signet.contacts.read%3Adirectory%2Csignet.contacts.read%3Atier%2Csignet.contacts.blocks.read"
        ));
        assert!(l.web.starts_with("https://mysignet.app/?pair=1&v=2&app="));
        assert!(l.app_link.starts_with("https://mysignet.app/pair?v=2&app="));
    }
}
