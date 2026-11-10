//! Test doubles: a fake My Signet (NIP-46 signer side and contacts-rail side)
//! on the crate's in-memory relay network.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use decented_signet::contacts_wire::{
    format_pairing_code, pairing_code, projection_tag, proposal_tag,
};
use decented_signet::relay::{Connector, FakeNetwork, Relay, RelayMsg, Subscription};
use decented_signet::{SignInEvent, Signet, SignetConfig};
use nostr::nips::nip44;
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp, Url};
use serde_json::{Value, json};

pub const RELAY: &str = "wss://relay.test";
pub const APP_ID: &str = "twangthang";
pub const SIGNIN_ORIGIN: &str = "https://decented.org";

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn temp_dir(tag: &str) -> PathBuf {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    std::env::temp_dir().join(format!("decented-signet-it-{tag}-{}", hex::encode(b)))
}

/// A config with test-sized timeouts on the fake network.
pub fn config(dir: &Path) -> SignetConfig {
    let mut c = SignetConfig::new(
        dir,
        APP_ID,
        "Twang Thang",
        Some("twangthang://signin".into()),
    );
    c.relays = vec![RELAY.to_string()];
    c.signin_origin = Some(SIGNIN_ORIGIN.to_string());
    c.pairing_timeout = Duration::from_secs(5);
    c.request_timeout = Duration::from_secs(5);
    c.fetch_timeout = Duration::from_millis(500);
    c.ack_timeout = Duration::from_secs(5);
    c
}

pub fn open(net: &FakeNetwork, dir: &Path, runtime: &Keys) -> Signet {
    Signet::with_connector(config(dir), runtime.clone(), Arc::new(net.clone()))
}

/// Sign `s` in as `persona` through a fresh fake My Signet; returns the signer.
pub fn sign_in_as(net: &FakeNetwork, s: &Signet, persona: &Keys) -> FakeMySignet {
    let signer = FakeMySignet::new(net, persona.clone());
    let si = s.sign_in();
    signer.handle_nostrconnect(si.nostrconnect_uri());
    let events = drain_sign_in(&si, Duration::from_secs(10));
    assert!(
        matches!(events.last(), Some(SignInEvent::Attested { .. })),
        "{events:?}"
    );
    signer
}

/// Poll `f` until it yields, or panic after `timeout`.
pub fn wait_for<T>(timeout: Duration, what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Collect sign-in events up to a terminal one.
pub fn drain_sign_in(s: &decented_signet::SignIn, timeout: Duration) -> Vec<SignInEvent> {
    let mut out = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        while let Some(ev) = s.poll() {
            let done = matches!(
                ev,
                SignInEvent::Attested { .. }
                    | SignInEvent::NoBunker { .. }
                    | SignInEvent::AttestationFailed { .. }
                    | SignInEvent::Failed { .. }
            );
            out.push(ev);
            if done {
                return out;
            }
        }
        assert!(Instant::now() < deadline, "sign-in did not finish: {out:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ─── Fake My Signet: NIP-46 signer ──────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairMode {
    Approve,
    /// Replies with an `error` (an explicit refusal).
    Refuse,
    /// Never replies (what My Signet's Deny button actually does).
    Ignore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignMode {
    Approve,
    /// `error: "user denied"` (My Signet's sign_event Deny).
    Deny,
    Ignore,
    /// Signs something other than what was asked.
    Substitute,
    /// Signs with a key other than the persona.
    WrongKey,
    PrivatiseWhileSigning,
    PermissionRevoked,
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub connects: usize,
    pub get_public_key: usize,
    pub signed_kinds: Vec<u16>,
}

/// Behaves like My Signet's NIP-46 server for a guardian persona: replies are
/// signed by the persona key, the `nostrconnect` reply echoes the secret,
/// `connect` from a known client is acked.
pub struct FakeMySignet {
    pub persona: Keys,
    /// The key the NIP-46 server speaks and listens as (= the bunker key in a
    /// `bunker://`). The persona itself for [`FakeMySignet::new`]; another key
    /// for a hardware-style bunker ([`FakeMySignet::bunker`]).
    pub transport: Keys,
    /// When set, `connect` must carry exactly this secret (a `bunker://`'s
    /// one-shot secret); anything else is refused.
    pub secret: Option<String>,
    pub pair: Arc<Mutex<PairMode>>,
    pub sign: Arc<Mutex<SignMode>>,
    pub stats: Arc<Mutex<Stats>>,
    pub public_profile: Arc<Mutex<Option<bool>>>,
    pub status_patch: Arc<Mutex<Value>>,
    relay: Arc<dyn Relay>,
    stop: Arc<AtomicBool>,
}

impl Drop for FakeMySignet {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn nip46_reply(persona: &Keys, client: &PublicKey, body: Value) -> Event {
    let ct = nip44::encrypt(
        persona.secret_key(),
        client,
        body.to_string(),
        nip44::Version::V2,
    )
    .unwrap();
    EventBuilder::new(Kind::NostrConnect, ct)
        .tag(Tag::public_key(*client))
        .sign_with_keys(persona)
        .unwrap()
}

impl FakeMySignet {
    pub fn new(net: &FakeNetwork, persona: Keys) -> FakeMySignet {
        let transport = persona.clone();
        Self::bunker(net, persona, transport, None)
    }

    /// A bunker whose own key is `transport` (not the persona): replies are
    /// sent and read under it, `sign_event` still signs as the persona, and
    /// `connect` must present `secret` when one is given.
    pub fn bunker(
        net: &FakeNetwork,
        persona: Keys,
        transport: Keys,
        secret: Option<&str>,
    ) -> FakeMySignet {
        let relay = net.connect(&[RELAY.to_string()]);
        let me = FakeMySignet {
            persona,
            transport,
            secret: secret.map(String::from),
            pair: Arc::new(Mutex::new(PairMode::Approve)),
            sign: Arc::new(Mutex::new(SignMode::Approve)),
            stats: Arc::new(Mutex::new(Stats::default())),
            public_profile: Arc::new(Mutex::new(None)),
            status_patch: Arc::new(Mutex::new(Value::Null)),
            relay,
            stop: Arc::new(AtomicBool::new(false)),
        };
        me.serve();
        me
    }

    fn serve(&self) {
        let mut sub = self.relay.subscribe(vec![
            nostr::Filter::new()
                .kind(Kind::NostrConnect)
                .pubkey(self.transport.public_key()),
        ]);
        let (persona, transport, secret, sign, stats, relay, stop) = (
            self.persona.clone(),
            self.transport.clone(),
            self.secret.clone(),
            self.sign.clone(),
            self.stats.clone(),
            self.relay.clone(),
            self.stop.clone(),
        );
        let public_profile = self.public_profile.clone();
        let status_patch = self.status_patch.clone();
        std::thread::spawn(move || {
            let mut known: std::collections::HashSet<PublicKey> = Default::default();
            while !stop.load(Ordering::Relaxed) {
                let Some(msg) = sub.try_recv() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                let RelayMsg::Event(ev) = msg else { continue };
                let Ok(pt) = nip44::decrypt(transport.secret_key(), &ev.pubkey, &ev.content) else {
                    continue;
                };
                let Ok(req) = serde_json::from_str::<Value>(&pt) else {
                    continue;
                };
                let id = req["id"].as_str().unwrap_or("").to_string();
                let method = req["method"].as_str().unwrap_or("");
                let reply = match method {
                    "connect" => {
                        stats.lock().unwrap().connects += 1;
                        // A known client reconnects without the one-shot secret.
                        let sent = req["params"][1].as_str();
                        match &secret {
                            Some(want)
                                if sent != Some(want.as_str()) && !known.contains(&ev.pubkey) =>
                            {
                                json!({"id": id, "error": "bad secret"})
                            }
                            _ => {
                                known.insert(ev.pubkey);
                                json!({"id": id, "result": "ack"})
                            }
                        }
                    }
                    "get_public_key" => {
                        stats.lock().unwrap().get_public_key += 1;
                        json!({"id": id, "result": persona.public_key().to_hex()})
                    }
                    "signet_get_public_profile" => {
                        if let Some(enabled) = *public_profile.lock().unwrap() {
                            let now = decented_signet::sharing::now_ms();
                            let mut value = json!({"v":1,"requestId":id,"clientPubkey":ev.pubkey.to_hex(),"personaPubkey":persona.public_key().to_hex(),"enabled":enabled,"checkedAt":now,"expiresAt":now+5000,"conditionalScopes":["sign_event:1:public_profile","sign_event:30762:public_profile"]});
                            if let Some(patch) = status_patch.lock().unwrap().as_object() {
                                for (k, v) in patch {
                                    value[k] = v.clone();
                                }
                            }
                            json!({"id":id,"result":value.to_string()})
                        } else {
                            json!({"id":id,"error":"method not supported"})
                        }
                    }
                    "sign_event" => {
                        let t: Value =
                            serde_json::from_str(req["params"][0].as_str().unwrap_or(""))
                                .unwrap_or(Value::Null);
                        let kind = t["kind"].as_u64().unwrap_or(1) as u16;
                        stats.lock().unwrap().signed_kinds.push(kind);
                        let tags: Vec<Tag> = t["tags"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|tg| {
                                let parts: Vec<String> = tg
                                    .as_array()?
                                    .iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect();
                                Tag::parse(parts).ok()
                            })
                            .collect();
                        let build = |content: &str| {
                            EventBuilder::new(Kind::Custom(kind), content)
                                .tags(tags.clone())
                                .allow_self_tagging()
                                .custom_created_at(Timestamp::from(
                                    t["created_at"].as_u64().unwrap_or(0),
                                ))
                        };
                        let mode = *sign.lock().unwrap();
                        match mode {
                            SignMode::Approve | SignMode::PrivatiseWhileSigning => {
                                let ev = build(t["content"].as_str().unwrap_or(""))
                                    .sign_with_keys(&persona)
                                    .unwrap();
                                if mode == SignMode::PrivatiseWhileSigning {
                                    *public_profile.lock().unwrap() = Some(false);
                                }
                                json!({"id": id, "result": serde_json::to_string(&ev).unwrap()})
                            }
                            SignMode::Deny => json!({"id": id, "error": "user denied"}),
                            SignMode::PermissionRevoked => {
                                json!({"id": id, "error": "permission not granted"})
                            }
                            SignMode::Ignore => continue,
                            SignMode::Substitute => {
                                let ev = build("something else").sign_with_keys(&persona).unwrap();
                                json!({"id": id, "result": serde_json::to_string(&ev).unwrap()})
                            }
                            SignMode::WrongKey => {
                                let ev = build(t["content"].as_str().unwrap_or(""))
                                    .sign_with_keys(&Keys::generate())
                                    .unwrap();
                                json!({"id": id, "result": serde_json::to_string(&ev).unwrap()})
                            }
                        }
                    }
                    _ => json!({"id": id, "error": "unsupported"}),
                };
                relay.publish(&nip46_reply(&transport, &ev.pubkey, reply));
            }
        });
    }

    /// What My Signet does when the person approves a `nostrconnect://` URI.
    pub fn handle_nostrconnect(&self, uri: &str) {
        let u = Url::parse(&uri.replace("nostrconnect://", "https://")).unwrap();
        let client = PublicKey::from_hex(u.host_str().unwrap()).unwrap();
        let secret = u
            .query_pairs()
            .find(|(k, _)| k == "secret")
            .unwrap()
            .1
            .into_owned();
        let body = match *self.pair.lock().unwrap() {
            PairMode::Approve => json!({"id": "c0", "result": secret}),
            PairMode::Refuse => json!({"id": "c0", "result": "", "error": "user denied"}),
            PairMode::Ignore => return,
        };
        self.relay
            .publish(&nip46_reply(&self.persona, &client, body));
    }

    /// What My Signet does when the App Link opens it: read `?nostrconnect=`.
    pub fn open_app_link(&self, link: &str) {
        let u = Url::parse(link).unwrap();
        assert_eq!(u.host_str(), Some("mysignet.app"));
        let inner = u
            .query_pairs()
            .find(|(k, _)| k == "nostrconnect")
            .unwrap()
            .1
            .into_owned();
        self.handle_nostrconnect(&inner);
    }

    pub fn stats(&self) -> Stats {
        self.stats.lock().unwrap().clone()
    }

    /// The `bunker://` URI a persona hands out for this signer.
    pub fn bunker_uri(&self, secret: &str) -> String {
        format!(
            "bunker://{}?relay={}&secret={secret}",
            self.transport.public_key().to_hex(),
            RELAY.replace(':', "%3A").replace('/', "%2F")
        )
    }
}

/// Publish a kind 0 for `keys`.
pub fn publish_profile(net: &FakeNetwork, keys: &Keys, content: &str) {
    let ev = EventBuilder::new(Kind::Metadata, content)
        .sign_with_keys(keys)
        .unwrap();
    assert!(net.hub(RELAY).publish(&ev));
}

// ─── Fake My Signet: contacts rail ──────────────────────────────────────────

pub struct FakeRail {
    pub rail: Keys,
    pub grant_id: String,
    pub app: PublicKey,
    pub challenge: String,
    pub relay: String,
    net: FakeNetwork,
}

fn query_of(link: &str) -> Vec<(String, String)> {
    Url::parse(link)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn q<'a>(qs: &'a [(String, String)], k: &str) -> &'a str {
    qs.iter()
        .find(|(kk, _)| kk == k)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("missing {k}"))
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

impl FakeRail {
    /// What My Signet does when the person approves a contacts-v2 grant:
    /// mint a grant id + rail key and send the ack (ephemeral kind 21237).
    /// `ack_relay` is the relay the projection will live on.
    pub fn approve(net: &FakeNetwork, web_link: &str, ack_relay: &str) -> FakeRail {
        let qs = query_of(web_link);
        assert_eq!(q(&qs, "pair"), "1");
        assert_eq!(q(&qs, "dir"), "owner");
        let app = PublicKey::from_hex(q(&qs, "app")).unwrap();
        let challenge = q(&qs, "challenge").to_string();
        let pairing_relay = q(&qs, "relay").to_string();
        let caps: Vec<String> = q(&qs, "caps").split(',').map(String::from).collect();
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).unwrap();
        let grant_id = hex::encode(b);
        let rail = Keys::generate();
        let ack = json!({
            "v": 2,
            "grantId": grant_id,
            "railPubkey": rail.public_key().to_hex(),
            "projectionTag": projection_tag(&grant_id),
            "proposalTag": proposal_tag(&grant_id, &app.to_hex()),
            "relay": ack_relay,
            "grantedCapabilities": caps,
            "maxStalenessSeconds": 21600,
            "challenge": challenge,
        });
        let eph = Keys::generate();
        let ct =
            nip44::encrypt(eph.secret_key(), &app, ack.to_string(), nip44::Version::V2).unwrap();
        let ev = EventBuilder::new(Kind::Custom(21237), ct)
            .tag(Tag::public_key(app))
            .sign_with_keys(&eph)
            .unwrap();
        net.connect(&[pairing_relay]).publish(&ev);
        FakeRail {
            rail,
            grant_id,
            app,
            challenge,
            relay: ack_relay.to_string(),
            net: net.clone(),
        }
    }

    /// The code My Signet expects the person to type.
    pub fn expected_code(&self) -> String {
        format_pairing_code(
            &pairing_code(
                &self.app.to_hex(),
                &self.challenge,
                &self.grant_id,
                &self.rail.public_key().to_hex(),
            )
            .unwrap(),
        )
    }

    fn seal(&self, body: &str) -> String {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        getrandom::fill(&mut key).unwrap();
        getrandom::fill(&mut iv).unwrap();
        let bucket = [4096usize, 8192, 16384, 32768, 65536]
            .into_iter()
            .find(|b| body.len() + 4 <= *b)
            .unwrap();
        let mut padded = vec![0u8; bucket];
        padded[..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
        padded[4..4 + body.len()].copy_from_slice(body.as_bytes());
        let ct = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(&Nonce::from(iv), padded.as_slice())
            .unwrap();
        let k = nip44::encrypt(
            self.rail.secret_key(),
            &self.app,
            B64.encode(key),
            nip44::Version::V2,
        )
        .unwrap();
        json!({"v": 2, "k": k, "iv": B64.encode(iv), "ct": B64.encode(ct), "b": bucket}).to_string()
    }

    /// Publish the encrypted projection (kind 30078) with `contacts`.
    pub fn publish(&self, contacts: Value, published_at: u64, revoked: bool) {
        let mut body = json!({
            "v": 2, "grantId": self.grant_id,
            "scopes": ["signet.contacts.read:directory", "signet.contacts.read:tier", "signet.contacts.blocks.read"],
            "frontier": {"maxClock": published_at, "opCount": 1, "publishedAt": published_at, "deviceId": "2".repeat(32)},
            "issuedAt": published_at, "expiresAt": published_at + 21_600,
            "contacts": contacts,
        });
        if revoked {
            body["revoked"] = json!(true);
        }
        let ev = EventBuilder::new(Kind::Custom(30078), self.seal(&body.to_string()))
            .tag(Tag::identifier(projection_tag(&self.grant_id)))
            .custom_created_at(Timestamp::from(published_at))
            .sign_with_keys(&self.rail)
            .unwrap();
        assert!(self.net.hub(&self.relay).publish(&ev));
    }
}

/// One projected contact.
pub fn contact(id: char, pk: &PublicKey, name: &str, tier: &str, blocked: bool) -> Value {
    let mut c = json!({
        "contactId": id.to_string().repeat(32),
        "identities": [{"pubkey": pk.to_hex()}],
        "displayName": name,
        "effectiveTier": tier,
    });
    if blocked {
        c["blocked"] = json!(true);
    }
    c
}

// ─── On-disk helpers ────────────────────────────────────────────────────────

pub fn signet_dir(dir: &Path) -> PathBuf {
    dir.join("signet")
}

/// How many `<name>.corrupt-*` copies sit next to the signet files.
pub fn aside_copies(dir: &Path, name: &str) -> usize {
    std::fs::read_dir(signet_dir(dir))
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with(&format!("{name}.corrupt-"))
                })
                .count()
        })
        .unwrap_or(0)
}

// ─── Shared scenario helpers ────────────────────────────────────────────────

/// Sign in on `runtime`, then close it. Returns the (still serving) fake My Signet.
pub fn sign_in_and_close(
    net: &FakeNetwork,
    dir: &Path,
    runtime: &Keys,
    persona: &Keys,
) -> FakeMySignet {
    let s = open(net, dir, runtime);
    let signer = sign_in_as(net, &s, persona);
    drop(s);
    signer
}

/// Every event of `kind` the (first) relay ever accepted.
pub fn published_of(net: &FakeNetwork, kind: u16) -> Vec<Event> {
    net.hub(RELAY)
        .published()
        .into_iter()
        .filter(|e| e.kind == Kind::Custom(kind))
        .collect()
}

/// A network whose relays take the NIP-46 traffic but silently drop events of
/// `kinds`: "a relay that never acks".
pub struct Dropping {
    pub net: FakeNetwork,
    pub kinds: Vec<Kind>,
}

struct DropRelay {
    inner: Arc<dyn Relay>,
    kinds: Vec<Kind>,
}

impl Connector for Dropping {
    fn connect(&self, urls: &[String]) -> Arc<dyn Relay> {
        Arc::new(DropRelay {
            inner: self.net.connect(urls),
            kinds: self.kinds.clone(),
        })
    }
}

impl Relay for DropRelay {
    fn publish(&self, ev: &Event) {
        if !self.kinds.contains(&ev.kind) {
            self.inner.publish(ev);
        }
    }
    fn subscribe(&self, filters: Vec<nostr::Filter>) -> Subscription {
        self.inner.subscribe(filters)
    }
    fn urls(&self) -> Vec<String> {
        self.inner.urls()
    }
}

pub fn open_dropping(net: &FakeNetwork, dir: &Path, runtime: &Keys, kinds: &[Kind]) -> Signet {
    let conn = Dropping {
        net: net.clone(),
        kinds: kinds.to_vec(),
    };
    Signet::with_connector(config(dir), runtime.clone(), Arc::new(conn))
}

pub const RELAY_B: &str = "wss://relay-b.test";

/// Open on both test relays.
pub fn open_two_relays(net: &FakeNetwork, dir: &Path, runtime: &Keys) -> Signet {
    let mut c = config(dir);
    c.relays = vec![RELAY.to_string(), RELAY_B.to_string()];
    Signet::with_connector(c, runtime.clone(), Arc::new(net.clone()))
}

/// Make `<name>.tmp` a directory, so the next save of `name` fails as it does
/// on a full disk (the atomic write cannot create its temp file).
pub fn block_saves(dir: &Path, name: &str) {
    std::fs::create_dir_all(signet_dir(dir).join(format!("{name}.tmp"))).unwrap();
}

pub fn unblock_saves(dir: &Path, name: &str) {
    let _ = std::fs::remove_dir_all(signet_dir(dir).join(format!("{name}.tmp")));
}

// ─── Two installs that have played together ─────────────────────────────────

/// A signed-in install and its fake My Signet.
pub struct Player {
    pub s: Signet,
    pub persona: Keys,
    pub runtime: Keys,
    pub signer: FakeMySignet,
    pub dir: PathBuf,
}

impl Drop for Player {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A new install signed in as a new persona, on the test relay.
pub fn player(net: &FakeNetwork, tag: &str) -> Player {
    let persona = Keys::generate();
    let runtime = Keys::generate();
    let signer = FakeMySignet::new(net, persona.clone());
    let dir = temp_dir(tag);
    let s = open(net, &dir, &runtime);
    let si = s.sign_in();
    signer.handle_nostrconnect(si.nostrconnect_uri());
    let events = drain_sign_in(&si, Duration::from_secs(10));
    assert!(
        matches!(events.last(), Some(SignInEvent::Attested { .. })),
        "{events:?}"
    );
    Player {
        s,
        persona,
        runtime,
        signer,
        dir,
    }
}

/// `a` has played with `b`: `b`'s attestation, runtime key, name and inbox
/// relays (the test relay) go into `a`'s book.
pub fn meet(a: &Player, b: &Player, name: &str) {
    a.s.played_with()
        .expect("signed in")
        .record(
            &b.s.attestation_json().expect("attested"),
            &b.runtime.public_key(),
            name,
            &b.s.inbox_relays(),
            now(),
        )
        .expect("recorded");
}

/// The book entry `a` holds for `b`.
pub fn entry_of(a: &Player, b: &Player) -> decented_signet::PlayedWithEntry {
    a.s.played_with()
        .unwrap()
        .by_persona(&b.persona.public_key())
        .expect("in the book")
}

pub fn payload() -> decented_signet::InvitePayload {
    decented_signet::InvitePayload {
        host_name: "Mum".into(),
        code: "ABCDEF".into(),
        expires_at: now() + 600,
    }
}

/// `from` invites `to` (who must be in `from`'s book).
pub fn send(from: &Player, to: &Player) {
    from.s
        .send_invite(&entry_of(from, to), payload())
        .wait(Duration::from_secs(10))
        .unwrap()
        .unwrap();
}

/// Pair contacts for `p` with the given projected contacts.
pub fn give_contacts(net: &FakeNetwork, s: &Signet, contacts: Value) -> FakeRail {
    let p = s.pair_contacts().unwrap();
    let t = Duration::from_secs(10);
    wait_for(t, "awaiting", || p.poll());
    let rail = FakeRail::approve(net, &p.links().web, RELAY);
    wait_for(t, "code", || p.poll());
    rail.publish(contacts, now(), false);
    p.confirm();
    let ev = wait_for(t, "paired", || p.poll());
    assert!(
        matches!(
            ev,
            decented_signet::PairingEvent::Paired {
                sync: decented_signet::ContactsSync::Updated { .. }
            }
        ),
        "{ev:?}"
    );
    rail
}
