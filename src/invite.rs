//! Game invites between installs: NIP-59 gift wraps addressed to the runtime
//! key of someone in the played-with book (kit rule 5). There is no
//! discovery: nothing here asks a relay whether a persona plays.
//!
//! Shape:
//! - **Rumor** (unsigned, kind [`INVITE_RUMOR_KIND`]), authored by the
//!   sender's runtime key. Content: [`InviteBody`] JSON (host name, room code,
//!   expiry, and the sender's own attestation). Tagged with NIP-40
//!   `expiration`.
//! - **Seal** (kind 13) signed by the sender's runtime key (nostr's NIP-59
//!   builder; it checks rumor author == seal author on open).
//! - **Wrap** (kind 1059) by a one-time key, `p` = recipient runtime key,
//!   NIP-40 `expiration` = the invite's `expires_at`.
//!
//! The receive policy ([`admit`]): the seal's key is in the played-with book,
//! or the carried attestation verifies, binds the seal's key and names a
//! persona in the book; and the persona is not a blocked contact. Everything
//! else is dropped silently. A field in the payload can never name the sender.

use nostr::nips::nip59::UnwrappedGift;
use nostr::{Event, EventBuilder, Filter, Keys, Kind, PublicKey, Tag, Timestamp};
use serde::{Deserialize, Serialize};

use crate::attestation::{AttestationError, verify_attestation};
use crate::contacts::Contact;
use crate::contacts_wire::sanitize_wire_text;
use crate::played_with::PlayedWithBook;

/// The rumor kind of a game invite. Never published bare: it only ever
/// exists inside a seal.
pub const INVITE_RUMOR_KIND: u16 = 20912;
/// Version 2 has no LAN `token` (version 1 had one).
pub const INVITE_VERSION: u8 = 2;
/// Longest wrap content we try to open.
pub const MAX_WRAP_CONTENT: usize = 16 * 1024;
/// Longest an invite may claim to stay valid.
pub const MAX_INVITE_LIFETIME: u64 = 7 * 86_400;
pub const MAX_HOST_NAME: usize = 64;
pub const MAX_CODE: usize = 16;
/// NIP-59 backdates wraps by up to two days, and an invite may live for
/// [`MAX_INVITE_LIFETIME`]: the inbox looks back this far, so a live invite is
/// still found after a restart.
pub const INBOX_LOOKBACK: u64 = MAX_INVITE_LIFETIME + 2 * 86_400;

/// What the host sends: who is hosting, the room code, and when the lobby
/// closes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitePayload {
    pub host_name: String,
    pub code: String,
    pub expires_at: u64,
}

/// The rumor content on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteBody {
    pub v: u8,
    pub host_name: String,
    pub code: String,
    pub expires_at: u64,
    /// The sender's attestation, as event JSON.
    pub attestation: String,
}

/// A wrap that opened and has a sound payload; the sender is not vetted yet
/// (see [`admit`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub payload: InvitePayload,
    /// The seal's key: the sender's runtime key.
    pub sender: PublicKey,
    /// The attestation the sender carried (event JSON), not yet checked.
    pub attestation: String,
}

/// A received invite that passed every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub payload: InvitePayload,
    /// The sender's persona: the played-with entry it matched.
    pub persona: PublicKey,
    /// The runtime key that sealed the invite.
    pub runtime: PublicKey,
    /// The name in the played-with book (may be empty).
    pub name: String,
    /// The sender's entry in our contacts, when they are one.
    pub contact: Option<Contact>,
    /// Gift-wrap event id (dedupe key).
    pub id: String,
    /// `Some(runtime)` when the sender's runtime key was not the one in the
    /// book: a verified attestation moved their persona to this key. The
    /// caller updates the entry with [`PlayedWithBook::rekey`], passing
    /// [`Invite::attestation`].
    pub new_runtime: Option<PublicKey>,
    /// The attestation the sender carried (event JSON).
    pub attestation: String,
}

impl Invite {
    /// What to show as the sender: the contact's name from our own contacts,
    /// else the name in the book, else the persona's short npub. (Never the
    /// host name in the payload: that field is the sender's own claim.)
    pub fn display_sender(&self) -> String {
        match &self.contact {
            Some(c) => c.display_name.clone(),
            None if !self.name.is_empty() => self.name.clone(),
            None => crate::contacts::short_npub(&self.persona),
        }
    }

    /// Whether the sender is one of our contacts.
    pub fn from_contact(&self) -> bool {
        self.contact.is_some()
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.payload.expires_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteError {
    NotAWrap,
    TooLarge,
    NotForUs,
    Undecryptable,
    WrongRumorKind,
    Malformed(&'static str),
    Expired,
    BadAttestation(AttestationError),
    /// Sender is blocked in our contacts.
    Blocked,
    /// Sender is not in the played-with book.
    NotInBook,
}

impl std::fmt::Display for InviteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for InviteError {}

fn safe_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Shape checks on a payload, sender and receiver side.
pub fn validate_payload(p: &InvitePayload, now: u64) -> Result<(), InviteError> {
    if p.host_name.is_empty() || sanitize_wire_text(&p.host_name, MAX_HOST_NAME) != p.host_name {
        return Err(InviteError::Malformed("host_name"));
    }
    if !safe_token(&p.code, MAX_CODE) {
        return Err(InviteError::Malformed("code"));
    }
    if p.expires_at <= now {
        return Err(InviteError::Expired);
    }
    if p.expires_at > now.saturating_add(MAX_INVITE_LIFETIME) {
        return Err(InviteError::Malformed("expires_at too far ahead"));
    }
    Ok(())
}

pub(crate) fn expiration_tag(at: u64) -> Tag {
    Tag::parse(["expiration", &at.to_string()]).expect("two-element tag")
}

fn expiration_of(ev: &Event) -> Option<u64> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.len() >= 2 && s[0] == "expiration")
            .then(|| s[1].parse::<u64>().ok())
            .flatten()
    })
}

/// Seal and wrap an invite from `sender` (this install's runtime key, whose
/// attestation is `attestation_json`) to the runtime key `to`. The wrapper
/// key is one-time.
pub async fn wrap_invite(
    sender: &Keys,
    attestation_json: &str,
    to: &PublicKey,
    payload: &InvitePayload,
) -> Result<Event, InviteError> {
    let body = InviteBody {
        v: INVITE_VERSION,
        host_name: payload.host_name.clone(),
        code: payload.code.clone(),
        expires_at: payload.expires_at,
        attestation: attestation_json.to_string(),
    };
    let content = serde_json::to_string(&body).map_err(|_| InviteError::Malformed("encode"))?;
    let rumor = EventBuilder::new(Kind::Custom(INVITE_RUMOR_KIND), content)
        .tag(expiration_tag(payload.expires_at))
        .build(sender.public_key());
    EventBuilder::gift_wrap(sender, to, rumor, [expiration_tag(payload.expires_at)])
        .await
        .map_err(|_| InviteError::Malformed("wrap"))
}

/// Open a wrap addressed to `me` and verify everything that does not depend
/// on who we have played with: size, addressee, NIP-40, seal signature and
/// author, rumor kind and shape, and payload. The carried attestation is
/// returned unchecked: [`admit`] decides how much it matters.
pub async fn open_invite(me: &Keys, wrap: &Event, now: u64) -> Result<Opened, InviteError> {
    let gift = unwrap_for_us(me, wrap, now).await?;
    invite_from_gift(gift, now)
}

/// The checks every wrap to our runtime key passes before anything reads its
/// rumor: kind, size, addressee, NIP-40, signature, and a seal that decrypts
/// and verifies. Game invites and friend replies share it; each then reads
/// only its own rumor kind.
pub(crate) async fn unwrap_for_us(
    me: &Keys,
    wrap: &Event,
    now: u64,
) -> Result<UnwrappedGift, InviteError> {
    if wrap.kind != Kind::GiftWrap {
        return Err(InviteError::NotAWrap);
    }
    if wrap.content.len() > MAX_WRAP_CONTENT {
        return Err(InviteError::TooLarge);
    }
    let me_hex = me.public_key().to_hex();
    let addressed = wrap.tags.iter().any(|t| {
        let s = t.as_slice();
        s.len() >= 2 && s[0] == "p" && s[1] == me_hex
    });
    if !addressed {
        return Err(InviteError::NotForUs);
    }
    if expiration_of(wrap).is_some_and(|x| x <= now) {
        return Err(InviteError::Expired);
    }
    if wrap.verify().is_err() {
        return Err(InviteError::NotAWrap);
    }
    UnwrappedGift::from_gift_wrap(me, wrap)
        .await
        .map_err(|_| InviteError::Undecryptable)
}

/// Read a game invite out of an unwrapped gift. Any other rumor kind (a
/// friend reply, say) is [`InviteError::WrongRumorKind`].
pub(crate) fn invite_from_gift(gift: UnwrappedGift, now: u64) -> Result<Opened, InviteError> {
    let rumor = gift.rumor;
    if rumor.kind != Kind::Custom(INVITE_RUMOR_KIND) || rumor.pubkey != gift.sender {
        return Err(InviteError::WrongRumorKind);
    }
    if rumor.content.len() > MAX_WRAP_CONTENT {
        return Err(InviteError::TooLarge);
    }
    let body: InviteBody =
        serde_json::from_str(&rumor.content).map_err(|_| InviteError::Malformed("body"))?;
    if body.v != INVITE_VERSION {
        return Err(InviteError::Malformed("version"));
    }
    let payload = InvitePayload {
        host_name: body.host_name,
        code: body.code,
        expires_at: body.expires_at,
    };
    validate_payload(&payload, now)?;
    Ok(Opened {
        payload,
        sender: gift.sender,
        attestation: body.attestation,
    })
}

/// Who an admitted invite is from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub persona: PublicKey,
    /// The name in the book.
    pub name: String,
    /// See [`Invite::new_runtime`].
    pub new_runtime: Option<PublicKey>,
}

/// The receive policy. `is_blocked` says whether a persona is a blocked
/// contact; a block beats everything, even someone you have played with.
///
/// 1. The seal's key is in the book: that entry's persona. (The carried
///    attestation may be stale or even absent in all but shape; it is only
///    held against the book if it verifies and names a *different* persona.)
/// 2. Otherwise the carried attestation must verify for the seal's key (a
///    persona signed it, for this game, in date), name a persona that is in
///    the book, and be strictly newer (`created_at`) than the attestation the
///    book holds for that persona; otherwise the sender is a stranger. The
///    sender has a new runtime key; it is reported.
/// 3. Anything else is [`InviteError::NotInBook`] (or the attestation's own
///    error), to be dropped silently.
pub fn admit(
    app_id: &str,
    book: &PlayedWithBook,
    opened: &Opened,
    is_blocked: &dyn Fn(&PublicKey) -> bool,
    now: u64,
) -> Result<Admitted, InviteError> {
    let carried = verify_attestation(app_id, opened.attestation.as_bytes(), &opened.sender, now);
    let (entry, new_runtime) = if let Some(entry) = book.by_runtime(&opened.sender) {
        if let Ok(info) = &carried
            && info.persona.to_hex() != entry.persona
        {
            return Err(InviteError::BadAttestation(
                AttestationError::WrongRuntimeKey,
            ));
        }
        (entry, None)
    } else {
        let info = carried.map_err(InviteError::BadAttestation)?;
        let entry = book
            .by_persona(&info.persona)
            .ok_or(InviteError::NotInBook)?;
        // A new key must come with an attestation strictly newer than the one
        // the book holds. An old install's key, still carrying an in-date
        // attestation, is a stranger (it must not take the entry back).
        if !crate::played_with::supersedes(&entry.attestation, &opened.attestation, true) {
            return Err(InviteError::NotInBook);
        }
        (entry, Some(opened.sender))
    };
    let persona = entry.persona_key().ok_or(InviteError::NotInBook)?;
    if is_blocked(&persona) {
        return Err(InviteError::Blocked);
    }
    Ok(Admitted {
        persona,
        name: entry.name,
        new_runtime,
    })
}

/// The relay filter for wraps to `me`: `kinds:[1059], #p:[me]`.
pub fn inbox_filter(me: &PublicKey, now: u64) -> Filter {
    Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(*me)
        .since(Timestamp::from(now.saturating_sub(INBOX_LOOKBACK)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::unsigned_attestation;

    const APP: &str = "testgame";

    fn attested(persona: &Keys, runtime: &Keys, now: u64) -> String {
        let ev = unsigned_attestation(APP, &persona.public_key(), &runtime.public_key(), now)
            .sign_with_keys(persona)
            .unwrap();
        serde_json::to_string(&ev).unwrap()
    }

    fn payload(now: u64) -> InvitePayload {
        InvitePayload {
            host_name: "Alex".into(),
            code: "ABCDEF".into(),
            expires_at: now + 600,
        }
    }

    fn book_with(persona: &Keys, runtime: &Keys, now: u64) -> PlayedWithBook {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        let dir = std::env::temp_dir().join(format!("decented-signet-invite-{}", hex::encode(b)));
        let book = PlayedWithBook::open(&dir, &Keys::generate().public_key(), APP);
        book.record(
            &attested(persona, runtime, now),
            &runtime.public_key(),
            "Alex",
            &[],
            now,
        )
        .unwrap();
        book
    }

    fn never(_: &PublicKey) -> bool {
        false
    }

    #[tokio::test]
    async fn round_trip() {
        let now = crate::unix_now();
        let (persona, sender, me) = (Keys::generate(), Keys::generate(), Keys::generate());
        let att = attested(&persona, &sender, now);
        let wrap = wrap_invite(&sender, &att, &me.public_key(), &payload(now))
            .await
            .unwrap();
        assert_eq!(wrap.kind, Kind::GiftWrap);
        assert_ne!(wrap.pubkey, sender.public_key(), "outer key is throwaway");
        assert_eq!(expiration_of(&wrap), Some(now + 600));
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert_eq!(o.payload, payload(now));
        assert_eq!(o.sender, sender.public_key());
        assert_eq!(o.attestation, att);
        // Not for a third party.
        let other = Keys::generate();
        assert_eq!(
            open_invite(&other, &wrap, now).await,
            Err(InviteError::NotForUs)
        );
        // The wire body has no LAN token.
        assert!(
            !serde_json::to_string(&InviteBody {
                v: 2,
                host_name: "a".into(),
                code: "b".into(),
                expires_at: 1,
                attestation: String::new()
            })
            .unwrap()
            .contains("token")
        );
    }

    #[tokio::test]
    async fn every_invite_gets_a_fresh_wrapper_key() {
        let now = crate::unix_now();
        let (persona, sender, me) = (Keys::generate(), Keys::generate(), Keys::generate());
        let att = attested(&persona, &sender, now);
        let a = wrap_invite(&sender, &att, &me.public_key(), &payload(now))
            .await
            .unwrap();
        let b = wrap_invite(&sender, &att, &me.public_key(), &payload(now))
            .await
            .unwrap();
        assert_ne!(a.pubkey, b.pubkey);
    }

    #[tokio::test]
    async fn expired_invites_are_dropped() {
        let now = crate::unix_now();
        let (persona, sender, me) = (Keys::generate(), Keys::generate(), Keys::generate());
        let wrap = wrap_invite(
            &sender,
            &attested(&persona, &sender, now),
            &me.public_key(),
            &payload(now),
        )
        .await
        .unwrap();
        assert_eq!(
            open_invite(&me, &wrap, now + 601).await,
            Err(InviteError::Expired)
        );
    }

    #[tokio::test]
    async fn policy_known_runtime_key_is_admitted_whatever_the_carried_attestation() {
        let now = crate::unix_now();
        let (persona, rt, me) = (Keys::generate(), Keys::generate(), Keys::generate());
        let book = book_with(&persona, &rt, now);
        // Valid attestation, an empty one, and garbage: the book already knows the key.
        for att in [
            attested(&persona, &rt, now),
            String::new(),
            "junk".to_string(),
        ] {
            let wrap = wrap_invite(&rt, &att, &me.public_key(), &payload(now))
                .await
                .unwrap();
            let o = open_invite(&me, &wrap, now).await.unwrap();
            let a = admit(APP, &book, &o, &never, now).unwrap();
            assert_eq!(
                (a.persona, a.name.as_str(), a.new_runtime),
                (persona.public_key(), "Alex", None)
            );
        }
        // But a valid attestation that names someone else is refused.
        let stranger = Keys::generate();
        let wrap = wrap_invite(
            &rt,
            &attested(&stranger, &rt, now),
            &me.public_key(),
            &payload(now),
        )
        .await
        .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert!(matches!(
            admit(APP, &book, &o, &never, now),
            Err(InviteError::BadAttestation(_))
        ));
    }

    #[tokio::test]
    async fn policy_new_runtime_key_needs_a_verified_attestation_naming_a_persona_in_the_book() {
        let now = crate::unix_now();
        let (persona, rt, me) = (Keys::generate(), Keys::generate(), Keys::generate());
        let book = book_with(&persona, &rt, now - 1_000);
        let new_rt = Keys::generate();
        let wrap = wrap_invite(
            &new_rt,
            &attested(&persona, &new_rt, now),
            &me.public_key(),
            &payload(now),
        )
        .await
        .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        let a = admit(APP, &book, &o, &never, now).unwrap();
        assert_eq!(
            (a.persona, a.new_runtime),
            (persona.public_key(), Some(new_rt.public_key()))
        );
        // A persona nobody has played with: dropped.
        let (nobody, nobody_rt) = (Keys::generate(), Keys::generate());
        let wrap = wrap_invite(
            &nobody_rt,
            &attested(&nobody, &nobody_rt, now),
            &me.public_key(),
            &payload(now),
        )
        .await
        .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert_eq!(
            admit(APP, &book, &o, &never, now),
            Err(InviteError::NotInBook)
        );
        // A replayed attestation of the real persona for the real key, sent by another key.
        let thief = Keys::generate();
        let wrap = wrap_invite(
            &thief,
            &attested(&persona, &rt, now),
            &me.public_key(),
            &payload(now),
        )
        .await
        .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert_eq!(
            admit(APP, &book, &o, &never, now),
            Err(InviteError::BadAttestation(
                AttestationError::WrongRuntimeKey
            ))
        );
        // No attestation at all.
        let wrap = wrap_invite(&thief, "", &me.public_key(), &payload(now))
            .await
            .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert!(matches!(
            admit(APP, &book, &o, &never, now),
            Err(InviteError::BadAttestation(_))
        ));
        // A tampered signature.
        let mut v: serde_json::Value =
            serde_json::from_str(&attested(&persona, &thief, now)).unwrap();
        v["pubkey"] = serde_json::json!(Keys::generate().public_key().to_hex());
        let wrap = wrap_invite(&thief, &v.to_string(), &me.public_key(), &payload(now))
            .await
            .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert!(matches!(
            admit(APP, &book, &o, &never, now),
            Err(InviteError::BadAttestation(_))
        ));
    }

    #[tokio::test]
    async fn policy_a_stale_attestation_cannot_take_an_entry_back() {
        let now = crate::unix_now();
        let (persona, me) = (Keys::generate(), Keys::generate());
        // The old install R1 (attested a day ago) and the newer R2 (an hour ago).
        let (r1, r2) = (Keys::generate(), Keys::generate());
        let old_att = attested(&persona, &r1, now - 86_400);
        let book = book_with(&persona, &r2, now - 3_600);
        // R1 is not in the book; its attestation is in date but older than R2's.
        let wrap = wrap_invite(&r1, &old_att, &me.public_key(), &payload(now))
            .await
            .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert_eq!(
            admit(APP, &book, &o, &never, now),
            Err(InviteError::NotInBook),
            "a stale attestation is a stranger"
        );
        assert_eq!(
            book.rekey(&persona.public_key(), &r1.public_key(), &old_att, now)
                .map(|_| ())
                .unwrap_err(),
            crate::played_with::BookError::BadAttestation(crate::played_with::STALE_ATTESTATION)
        );
        assert_eq!(
            book.by_persona(&persona.public_key()).unwrap().runtime,
            r2.public_key().to_hex()
        );
        // The same stale attestation, presented at a game (record), is refused too.
        assert!(
            book.record(&old_att, &r1.public_key(), "Alex", &[], now)
                .is_err()
        );
        // A newer attestation for a third key is admitted and may rekey.
        let r3 = Keys::generate();
        let new_att = attested(&persona, &r3, now);
        let wrap = wrap_invite(&r3, &new_att, &me.public_key(), &payload(now))
            .await
            .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        let a = admit(APP, &book, &o, &never, now).unwrap();
        assert_eq!(a.new_runtime, Some(r3.public_key()));
        book.rekey(&persona.public_key(), &r3.public_key(), &new_att, now)
            .unwrap();
        assert!(book.by_runtime(&r3.public_key()).is_some());
    }

    #[tokio::test]
    async fn policy_blocks_beat_the_book() {
        let now = crate::unix_now();
        let (persona, rt, me) = (Keys::generate(), Keys::generate(), Keys::generate());
        let book = book_with(&persona, &rt, now - 1_000);
        let blocked = persona.public_key();
        let wrap = wrap_invite(
            &rt,
            &attested(&persona, &rt, now),
            &me.public_key(),
            &payload(now),
        )
        .await
        .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert_eq!(
            admit(APP, &book, &o, &|p| *p == blocked, now),
            Err(InviteError::Blocked)
        );
        // Also on the new-key path.
        let new_rt = Keys::generate();
        let wrap = wrap_invite(
            &new_rt,
            &attested(&persona, &new_rt, now),
            &me.public_key(),
            &payload(now),
        )
        .await
        .unwrap();
        let o = open_invite(&me, &wrap, now).await.unwrap();
        assert_eq!(
            admit(APP, &book, &o, &|p| *p == blocked, now),
            Err(InviteError::Blocked)
        );
    }

    #[test]
    fn payload_validation() {
        let now = 1_000;
        assert!(validate_payload(&payload(now), now).is_ok());
        let bad = |f: fn(&mut InvitePayload)| {
            let mut p = payload(now);
            f(&mut p);
            validate_payload(&p, now).is_err()
        };
        assert!(bad(|p| p.host_name = String::new()));
        assert!(bad(|p| p.host_name = "a\u{202e}b".into()));
        assert!(bad(|p| p.code = "AB C".into()));
        assert!(bad(|p| p.expires_at = 999));
        assert!(bad(|p| p.expires_at = 1_000 + MAX_INVITE_LIFETIME + 1));
    }
}
