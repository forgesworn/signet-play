//! NIP-46 client: the client-initiated (`nostrconnect://`) pairing, persisted
//! sessions, and the request loop (`connect`, `get_public_key`, `sign_event`).
//!
//! Ported from a vendored copy of `signet-nip46-client` in an earlier game codebase (see `NOTICE`):
//! the URI builder, the one-shot `secret`, the constant-time echo check (a bare
//! `"ack"` is refused: the relay sees our `#p` subscription and could race to
//! impersonate the signer), refusal on a non-empty `error`, and the secret-less
//! persisted session are kept as they were. The transport differs: instead of
//! wrapping rust-nostr's `NostrConnect` (which owns its own relay pool) the
//! requests run over this crate's [`Relay`], so the whole flow is testable
//! against an in-memory relay and a fake signer. The wire is unchanged: kind
//! 24133, NIP-44, `{id, method, params}` / `{id, result, error}`.

use std::sync::Arc;
use std::time::Duration;

use nostr::nips::nip44;
use nostr::{Event, EventBuilder, Filter, Keys, Kind, PublicKey, Tag, UnsignedEvent, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::relay::{Relay, RelayMsg, Subscription};

/// Errors from pairing, restoring, or a request to the signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A malformed relay URL or URI.
    Uri(String),
    /// An invalid persisted app secret key.
    Key(String),
    /// Relay transport trouble.
    Connect(String),
    /// The signer refused or failed the request.
    Signer(String),
    /// No answer in time (the signer is closed, not serving, or the user
    /// dismissed the prompt without answering).
    Timeout,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Uri(m) => write!(f, "invalid NIP-46 URI: {m}"),
            Error::Key(m) => write!(f, "invalid persisted app secret key: {m}"),
            Error::Connect(m) => write!(f, "NIP-46 transport error: {m}"),
            Error::Signer(m) => write!(f, "the signer said no: {m}"),
            Error::Timeout => write!(f, "no answer from the signer in time"),
        }
    }
}

impl std::error::Error for Error {}

/// Everything needed to talk to the signer again on a later launch. Holds no
/// user key: `app_secret_key` is the throwaway NIP-46 *client* key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSession {
    /// Hex secret of the NIP-46 client keypair (not the persona).
    pub app_secret_key: String,
    /// Hex pubkey of the remote signer (the key that answers requests).
    pub remote_signer: String,
    /// Relays the signer listens on.
    pub relays: Vec<String>,
    /// Hex pubkey of the persona (`get_public_key`).
    pub persona: String,
}

impl PersistedSession {
    /// The equivalent `bunker://` URI (secret-less), for display or for any
    /// other NIP-46 client.
    pub fn bunker_uri(&self) -> String {
        let mut url = match Url::parse(&format!("bunker://{}", self.remote_signer)) {
            Ok(u) => u,
            Err(_) => return String::new(),
        };
        {
            let mut q = url.query_pairs_mut();
            for r in &self.relays {
                q.append_pair("relay", r);
            }
        }
        url.to_string()
    }
}

/// A fresh single-use connect secret: 16 bytes from the OS CSPRNG, hex.
pub(crate) fn generate_connect_secret() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS random source");
    hex::encode(b)
}

/// A parsed `bunker://<signer pubkey>?relay=<wss>&relay=<wss>&secret=<one-shot>`.
#[derive(Clone, PartialEq, Eq)]
pub struct BunkerUri {
    /// The key that answers requests (for My Signet's sign-in this is the persona).
    pub remote: PublicKey,
    /// The relays it listens on: `wss://`, deduplicated, at most [`MAX_BUNKER_RELAYS`].
    pub relays: Vec<String>,
    /// The one-shot pairing secret, if the URI carries one. Never persisted.
    pub secret: Option<String>,
}

/// The client key stays out of any debug print: the signer still answers it.
impl std::fmt::Debug for PersistedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistedSession")
            .field("app_secret_key", &"<redacted>")
            .field("remote_signer", &self.remote_signer)
            .field("relays", &self.relays)
            .field("persona", &self.persona)
            .finish()
    }
}

impl std::fmt::Debug for BunkerUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BunkerUri")
            .field("remote", &self.remote)
            .field("relays", &self.relays)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Most relays taken from one `bunker://` URI.
pub const MAX_BUNKER_RELAYS: usize = 8;
const MAX_BUNKER_URI: usize = 2048;
const MAX_BUNKER_SECRET: usize = 256;

/// Parse a `bunker://` URI (NIP-46): a 64-hex signer pubkey, at least one
/// `relay=` that is a `wss://` URL, and an optional `secret=`. Anything else
/// (another scheme, a bad key, no usable relay, an oversize value) is an
/// [`Error::Uri`]. Relays other than `wss://` are skipped, not trusted.
pub fn parse_bunker_uri(uri: &str) -> Result<BunkerUri, Error> {
    let uri = uri.trim();
    if uri.len() > MAX_BUNKER_URI {
        return Err(Error::Uri("bunker URI is too long".into()));
    }
    if !uri
        .get(..9)
        .is_some_and(|p| p.eq_ignore_ascii_case("bunker://"))
    {
        return Err(Error::Uri("not a bunker:// URI".into()));
    }
    let url = Url::parse(uri).map_err(|e| Error::Uri(e.to_string()))?;
    let host = url.host_str().unwrap_or("");
    if host.len() != 64 {
        return Err(Error::Uri("bunker URI has no signer key".into()));
    }
    let remote = PublicKey::from_hex(host).map_err(|e| Error::Uri(e.to_string()))?;
    let mut relays: Vec<String> = Vec::new();
    let mut secret = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "relay" => {
                let r = v.trim().trim_end_matches('/').to_string();
                let ok = r.len() <= 256
                    && r.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("wss://"))
                    && Url::parse(&r).is_ok_and(|u| u.host_str().is_some_and(|h| !h.is_empty()));
                if ok && !relays.contains(&r) && relays.len() < MAX_BUNKER_RELAYS {
                    relays.push(r);
                }
            }
            "secret" if secret.is_none() => {
                if v.len() > MAX_BUNKER_SECRET {
                    return Err(Error::Uri("bunker secret is too long".into()));
                }
                if !v.is_empty() {
                    secret = Some(v.into_owned());
                }
            }
            _ => {}
        }
    }
    if relays.is_empty() {
        return Err(Error::Uri("bunker URI names no wss:// relay".into()));
    }
    Ok(BunkerUri {
        remote,
        relays,
        secret,
    })
}

/// Build the `nostrconnect://` URI per current NIP-46: app pubkey, every relay,
/// the one-shot `secret`, `perms`, and the app name both as `name=` and as
/// `metadata={"name":..}` (My Signet reads `metadata` first). Requested
/// permissions remain subject to explicit signer approval. No `url` in the metadata: My Signet would then demand that a
/// `callback` share its origin. Every query value is form-urlencoded.
pub fn build_nostrconnect_uri(
    app_pk: &PublicKey,
    relays: &[String],
    app_name: &str,
    secret: &str,
    perms: &str,
) -> Result<String, Error> {
    let mut url = Url::parse(&format!("nostrconnect://{}", app_pk.to_hex()))
        .map_err(|e| Error::Uri(e.to_string()))?;
    {
        let mut q = url.query_pairs_mut();
        for relay in relays {
            q.append_pair("relay", relay.trim_end_matches('/'));
        }
        q.append_pair("secret", secret);
        if !perms.is_empty() {
            q.append_pair("perms", perms);
        }
        q.append_pair("name", app_name);
        q.append_pair("metadata", &json!({ "name": app_name }).to_string());
    }
    Ok(url.to_string())
}

#[derive(Deserialize)]
struct Reply {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// What a decrypted client-initiated `connect` reply means for the handshake.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConnectVerdict {
    Accept,
    Refused(String),
    Ignore,
}

/// Only an exact (constant-time) echo of our secret is accepted; a non-empty
/// `error` refuses the pairing; anything else (incl. `"ack"`) is ignored.
pub(crate) fn classify_connect_reply(
    result: Option<&str>,
    error: Option<&str>,
    secret: &str,
) -> ConnectVerdict {
    use subtle::ConstantTimeEq;
    if let Some(e) = error.filter(|e| !e.is_empty()) {
        return ConnectVerdict::Refused(e.to_string());
    }
    match result {
        Some(r) if bool::from(r.as_bytes().ct_eq(secret.as_bytes())) => ConnectVerdict::Accept,
        _ => ConnectVerdict::Ignore,
    }
}

/// Longest we hold back "listening" while some relay neither answers nor fails.
pub const LISTEN_GRACE: Duration = Duration::from_secs(10);

/// Largest kind-24133 content we try to decrypt.
const MAX_NIP46_CONTENT: usize = 256 * 1024;

fn decrypt_reply(event: &Event, app_keys: &Keys) -> Option<Reply> {
    if event.kind != Kind::NostrConnect
        || event.content.len() > MAX_NIP46_CONTENT
        || event.verify().is_err()
    {
        return None;
    }
    let plaintext = nip44::decrypt(app_keys.secret_key(), &event.pubkey, &event.content).ok()?;
    serde_json::from_str(&plaintext).ok()
}

/// `Some(Ok(signer))` = accepted; `Some(Err(msg))` = refused; `None` = not
/// ours / junk / wrong secret (never aborts the wait).
pub(crate) fn accept_connect_event(
    event: &Event,
    app_keys: &Keys,
    secret: &str,
) -> Option<Result<PublicKey, String>> {
    let reply = decrypt_reply(event, app_keys)?;
    match classify_connect_reply(reply.result.as_deref(), reply.error.as_deref(), secret) {
        ConnectVerdict::Accept => Some(Ok(event.pubkey)),
        ConnectVerdict::Refused(e) => Some(Err(e)),
        ConnectVerdict::Ignore => None,
    }
}

fn reply_filter(app: &PublicKey) -> Filter {
    Filter::new().kind(Kind::NostrConnect).pubkey(*app)
}

/// A client-initiated pairing waiting for the signer to scan and approve. The
/// relay subscription is open from construction, so no reply can be missed.
pub struct PendingPair {
    app_keys: Keys,
    secret: String,
    relays: Vec<String>,
    relay: Arc<dyn Relay>,
    sub: Subscription,
}

impl PendingPair {
    /// Mint a fresh app key + secret, open the reply subscription on `relay`
    /// (which must talk to `relays`), and return the `nostrconnect://` URI.
    pub fn start(
        relay: Arc<dyn Relay>,
        app_name: &str,
        perms: &str,
    ) -> Result<(String, PendingPair), Error> {
        let relays = relay.urls();
        if relays.is_empty() {
            return Err(Error::Uri("at least one relay is required".into()));
        }
        for r in &relays {
            Url::parse(r).map_err(|e| Error::Uri(e.to_string()))?;
        }
        let app_keys = Keys::generate();
        let secret = generate_connect_secret();
        let uri =
            build_nostrconnect_uri(&app_keys.public_key(), &relays, app_name, &secret, perms)?;
        let sub = relay.subscribe(vec![reply_filter(&app_keys.public_key())]);
        Ok((
            uri,
            PendingPair {
                app_keys,
                secret,
                relays,
                relay,
                sub,
            },
        ))
    }

    /// Wait for the signer's `connect` reply carrying our secret.
    ///
    /// `on_listening` runs once, when every relay has answered the reply
    /// subscription (EOSE, or failed to connect), or after [`LISTEN_GRACE`]:
    /// the moment it is safe to hand the URI to the signer. The reply is
    /// ephemeral, so one sent before anybody listens is lost.
    pub async fn await_signer<F: FnOnce() + Send>(
        mut self,
        timeout: Duration,
        on_listening: F,
    ) -> Result<RemoteSigner, Error> {
        let mut on_listening = Some(on_listening);
        let want = self.sub.relays();
        let wait = async {
            let mut eose = 0;
            let grace = tokio::time::sleep(LISTEN_GRACE);
            tokio::pin!(grace);
            loop {
                let msg = tokio::select! {
                    _ = &mut grace, if on_listening.is_some() => {
                        if let Some(f) = on_listening.take() { f() }
                        continue;
                    }
                    msg = self.sub.recv() => msg,
                };
                match msg {
                    Some(RelayMsg::Event(ev)) => {
                        if let Some(r) = accept_connect_event(&ev, &self.app_keys, &self.secret) {
                            if let Some(f) = on_listening.take() {
                                f()
                            }
                            return r.map_err(Error::Signer);
                        }
                    }
                    Some(RelayMsg::Eose) => {
                        eose += 1;
                        if eose >= want
                            && let Some(f) = on_listening.take()
                        {
                            f()
                        }
                    }
                    None => return Err(Error::Connect("relay subscription closed".into())),
                }
            }
        };
        let remote = tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Error::Timeout)??;
        Ok(RemoteSigner {
            app_keys: self.app_keys,
            remote,
            relays: self.relays,
            relay: self.relay,
            timeout,
        })
    }
}

/// A paired signer. Every call is one round trip over the relays.
pub struct RemoteSigner {
    app_keys: Keys,
    remote: PublicKey,
    relays: Vec<String>,
    relay: Arc<dyn Relay>,
    timeout: Duration,
}

/// How far a signer may restamp `created_at` on a template we sent.
const CREATED_AT_SLACK: u64 = 600;

impl RemoteSigner {
    /// Reconnect a persisted session over `relay` (which must talk to
    /// `session.relays`). Offline: nothing is sent until the first request.
    pub fn restore(
        session: &PersistedSession,
        relay: Arc<dyn Relay>,
        timeout: Duration,
    ) -> Result<RemoteSigner, Error> {
        let sk = nostr::SecretKey::from_hex(&session.app_secret_key)
            .map_err(|e| Error::Key(e.to_string()))?;
        let remote =
            PublicKey::from_hex(&session.remote_signer).map_err(|e| Error::Uri(e.to_string()))?;
        Ok(RemoteSigner {
            app_keys: Keys::new(sk),
            remote,
            relays: session.relays.clone(),
            relay,
            timeout,
        })
    }

    /// A signer for a `bunker://` URI, over `relay` (which must talk to
    /// `bunker.relays`). The client key is fresh and exists nowhere else.
    /// Nothing is sent until [`RemoteSigner::connect_with_secret`].
    pub fn from_bunker(
        bunker: &BunkerUri,
        relay: Arc<dyn Relay>,
        timeout: Duration,
    ) -> RemoteSigner {
        RemoteSigner {
            app_keys: Keys::generate(),
            remote: bunker.remote,
            relays: bunker.relays.clone(),
            relay,
            timeout,
        }
    }

    pub fn persist(&self, persona: &PublicKey) -> PersistedSession {
        PersistedSession {
            app_secret_key: self.app_keys.secret_key().to_secret_hex(),
            remote_signer: self.remote.to_hex(),
            relays: self.relays.clone(),
            persona: persona.to_hex(),
        }
    }

    pub fn remote(&self) -> PublicKey {
        self.remote
    }

    pub fn client_public_key(&self) -> PublicKey {
        self.app_keys.public_key()
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// One NIP-46 request. Replies that do not decrypt, do not parse, or carry
    /// another id are ignored; `auth_url` challenges are ignored (My Signet
    /// does not send them); a non-empty `error` fails the request.
    pub async fn request(&self, method: &str, params: Vec<String>) -> Result<String, Error> {
        let id = generate_connect_secret();
        self.request_with_id(&id, method, params).await
    }

    /// A caller-bound request id, used by authenticated extension responses.
    pub(crate) async fn request_with_id(&self, id: &str, method: &str, params: Vec<String>) -> Result<String, Error> {
        let body = json!({ "id": id, "method": method, "params": params }).to_string();
        let content = nip44::encrypt(
            self.app_keys.secret_key(),
            &self.remote,
            body,
            nip44::Version::V2,
        )
        .map_err(|e| Error::Connect(e.to_string()))?;
        let event = EventBuilder::new(Kind::NostrConnect, content)
            .tag(Tag::public_key(self.remote))
            .sign_with_keys(&self.app_keys)
            .map_err(|e| Error::Connect(e.to_string()))?;
        let mut sub = self.relay.subscribe(vec![
            reply_filter(&self.app_keys.public_key()).author(self.remote),
        ]);
        self.relay.publish(&event);
        let wait = async {
            loop {
                match sub.recv().await {
                    Some(RelayMsg::Event(ev)) => {
                        if ev.pubkey != self.remote {
                            continue;
                        }
                        let recipients: Vec<_> = ev.tags.iter().filter(|tag| tag.as_slice().first().is_some_and(|v| v == "p")).collect();
                        if recipients.len() != 1 || recipients[0].as_slice().get(1) != Some(&self.app_keys.public_key().to_hex()) {
                            continue;
                        }
                        let Some(reply) = decrypt_reply(&ev, &self.app_keys) else {
                            continue;
                        };
                        if reply.id.as_deref() != Some(id)
                            || reply.result.as_deref() == Some("auth_url")
                        {
                            continue;
                        }
                        if let Some(e) = reply.error.filter(|e| !e.is_empty()) {
                            return Err(Error::Signer(e));
                        }
                        return reply
                            .result
                            .ok_or_else(|| Error::Signer("empty reply".into()));
                    }
                    Some(RelayMsg::Eose) => {}
                    None => return Err(Error::Connect("relay subscription closed".into())),
                }
            }
        };
        tokio::time::timeout(self.timeout, wait)
            .await
            .map_err(|_| Error::Timeout)?
    }

    /// `connect` for a restored session (My Signet acks a known client).
    pub async fn connect(&self) -> Result<(), Error> {
        self.connect_with_secret(None).await
    }

    /// `connect` presenting the one-shot secret of a `bunker://` URI. The
    /// secret is sent in this one request and kept nowhere.
    pub async fn connect_with_secret(&self, secret: Option<&str>) -> Result<(), Error> {
        self.request(
            "connect",
            vec![self.remote.to_hex(), secret.unwrap_or("").to_string()],
        )
        .await
        .map(|_| ())
    }

    pub async fn get_public_key(&self) -> Result<PublicKey, Error> {
        let hex = self.request("get_public_key", Vec::new()).await?;
        PublicKey::from_hex(hex.trim())
            .map_err(|e| Error::Signer(format!("bad pubkey in reply: {e}")))
    }

    /// Ask the persona to sign `unsigned`. The reply must be a validly signed
    /// event by `persona` with the same kind, content and tags (a signer may
    /// restamp `created_at` by up to ten minutes).
    pub async fn sign_event(
        &self,
        unsigned: &UnsignedEvent,
        persona: &PublicKey,
    ) -> Result<Event, Error> {
        let template = json!({
            "kind": unsigned.kind.as_u16(),
            "pubkey": persona.to_hex(),
            "created_at": unsigned.created_at.as_secs(),
            "tags": unsigned.tags,
            "content": unsigned.content,
        })
        .to_string();
        let reply = self.request("sign_event", vec![template]).await?;
        let ev: Event = serde_json::from_str(&reply)
            .map_err(|e| Error::Signer(format!("bad event in reply: {e}")))?;
        check_signed(&ev, unsigned, persona)?;
        Ok(ev)
    }
}

pub(crate) fn check_signed(
    ev: &Event,
    asked: &UnsignedEvent,
    persona: &PublicKey,
) -> Result<(), Error> {
    if ev.verify().is_err() {
        return Err(Error::Signer("the signed event does not verify".into()));
    }
    if ev.pubkey != *persona {
        return Err(Error::Signer(
            "signed by a different key than the persona".into(),
        ));
    }
    if ev.kind != asked.kind || ev.content != asked.content || ev.tags != asked.tags {
        return Err(Error::Signer(
            "the signed event is not the one we asked for".into(),
        ));
    }
    if ev.created_at.as_secs().abs_diff(asked.created_at.as_secs()) > CREATED_AT_SLACK {
        return Err(Error::Signer(
            "the signed event has a far-off timestamp".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{Connector, FakeNetwork};

    fn query(uri: &str) -> Vec<(String, String)> {
        Url::parse(uri)
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn get<'a>(q: &'a [(String, String)], key: &str) -> Option<&'a str> {
        q.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn nostrconnect_uri_carries_secret_relays_perms_and_name() {
        let net = FakeNetwork::new();
        let relay = net.connect(&["wss://relay.one".into(), "wss://relay.two".into()]);
        let (uri, pending) = PendingPair::start(relay, "Twang Thang", "sign_event:30420").unwrap();
        assert!(uri.starts_with("nostrconnect://"));
        let q = query(&uri);
        let secret = get(&q, "secret").expect("URI must carry a secret");
        assert_eq!(secret.len(), 32);
        assert_eq!(secret, pending.secret);
        let relays: Vec<&str> = q
            .iter()
            .filter(|(k, _)| k == "relay")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(relays, ["wss://relay.one", "wss://relay.two"]);
        assert_eq!(get(&q, "perms"), Some("sign_event:30420"));
        assert_eq!(get(&q, "name"), Some("Twang Thang"));
        let meta: serde_json::Value = serde_json::from_str(get(&q, "metadata").unwrap()).unwrap();
        assert_eq!(meta, json!({"name": "Twang Thang"}));
        assert_eq!(
            Url::parse(&uri).unwrap().host_str().unwrap(),
            pending.app_keys.public_key().to_hex()
        );
    }

    #[test]
    fn each_pairing_mints_a_fresh_secret_and_key() {
        let net = FakeNetwork::new();
        let mk = || {
            PendingPair::start(net.connect(&["wss://r".into()]), "x", "")
                .unwrap()
                .1
        };
        let (a, b) = (mk(), mk());
        assert_ne!(a.secret, b.secret);
        assert_ne!(a.app_keys.public_key(), b.app_keys.public_key());
    }

    #[test]
    fn empty_relay_list_is_refused() {
        let net = FakeNetwork::new();
        assert!(matches!(
            PendingPair::start(net.connect(&[]), "x", ""),
            Err(Error::Uri(_))
        ));
    }

    #[test]
    fn connect_reply_predicate_follows_nip46() {
        use ConnectVerdict::*;
        assert_eq!(
            classify_connect_reply(Some("s3cret"), None, "s3cret"),
            Accept
        );
        assert_eq!(
            classify_connect_reply(Some("s3cret"), Some(""), "s3cret"),
            Accept
        );
        assert_eq!(classify_connect_reply(Some("ack"), None, "s3cret"), Ignore);
        assert_eq!(
            classify_connect_reply(Some("s3cre"), None, "s3cret"),
            Ignore
        );
        assert_eq!(classify_connect_reply(None, None, "s3cret"), Ignore);
        assert_eq!(
            classify_connect_reply(Some("s3cret"), Some("denied"), "s3cret"),
            Refused("denied".into())
        );
    }

    fn reply_event(signer: &Keys, to: &PublicKey, json: &str) -> Event {
        let ct = nip44::encrypt(signer.secret_key(), to, json, nip44::Version::V2).unwrap();
        EventBuilder::new(Kind::NostrConnect, ct)
            .tag(Tag::public_key(*to))
            .sign_with_keys(signer)
            .unwrap()
    }

    #[test]
    fn accept_connect_event_cases() {
        let app = Keys::generate();
        let signer = Keys::generate();
        let secret = "0123456789abcdef0123456789abcdef";
        let ok = reply_event(
            &signer,
            &app.public_key(),
            &format!(r#"{{"id":"r1","result":"{secret}"}}"#),
        );
        assert_eq!(
            accept_connect_event(&ok, &app, secret),
            Some(Ok(signer.public_key()))
        );
        let ack = reply_event(&signer, &app.public_key(), r#"{"id":"r2","result":"ack"}"#);
        assert_eq!(accept_connect_event(&ack, &app, secret), None);
        let err = reply_event(&signer, &app.public_key(), r#"{"id":"r","error":"denied"}"#);
        assert_eq!(
            accept_connect_event(&err, &app, secret),
            Some(Err("denied".into()))
        );
        let junk = reply_event(&signer, &app.public_key(), "not json");
        assert_eq!(accept_connect_event(&junk, &app, secret), None);
        let other = Keys::generate();
        let misaddressed = reply_event(&signer, &other.public_key(), r#"{"result":"x"}"#);
        assert_eq!(accept_connect_event(&misaddressed, &app, secret), None);
        let note = EventBuilder::text_note("ack")
            .sign_with_keys(&signer)
            .unwrap();
        assert_eq!(accept_connect_event(&note, &app, secret), None);
    }

    #[test]
    fn persisted_session_round_trips_and_restores() {
        let net = FakeNetwork::new();
        let relays = vec!["wss://relay.one".to_string()];
        let p = PersistedSession {
            app_secret_key: Keys::generate().secret_key().to_secret_hex(),
            remote_signer: Keys::generate().public_key().to_hex(),
            relays: relays.clone(),
            persona: Keys::generate().public_key().to_hex(),
        };
        let back: PersistedSession =
            serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
        let s = RemoteSigner::restore(&p, net.connect(&relays), Duration::from_secs(1)).unwrap();
        assert_eq!(s.app_keys.secret_key().to_secret_hex(), p.app_secret_key);
        assert!(
            p.bunker_uri()
                .starts_with(&format!("bunker://{}?relay=", p.remote_signer))
        );
        assert!(!p.bunker_uri().contains("secret"));
        let bad = PersistedSession {
            app_secret_key: "deadbeef".into(),
            ..p
        };
        assert!(matches!(
            RemoteSigner::restore(&bad, net.connect(&relays), Duration::from_secs(1)),
            Err(Error::Key(_))
        ));
    }

    #[test]
    fn bunker_uri_parses_relays_and_secret() {
        let pk = Keys::generate().public_key().to_hex();
        let b = parse_bunker_uri(&format!(
            "bunker://{pk}?relay=wss%3A%2F%2Fa.example&relay=wss://b.example/&relay=wss://a.example&relay=ws://c.example&secret=s3cretvalue"
        ))
        .unwrap();
        assert_eq!(b.remote.to_hex(), pk);
        assert_eq!(b.relays, ["wss://a.example", "wss://b.example"]);
        assert_eq!(b.secret.as_deref(), Some("s3cretvalue"));
        assert!(!format!("{b:?}").contains("s3cretvalue"));
        // No secret is fine; the session's own secret-less form round-trips.
        let s = PersistedSession {
            app_secret_key: Keys::generate().secret_key().to_secret_hex(),
            remote_signer: pk.clone(),
            relays: vec!["wss://r.example".into()],
            persona: pk.clone(),
        };
        let back = parse_bunker_uri(&s.bunker_uri()).unwrap();
        assert_eq!(
            (back.relays, back.secret),
            (vec!["wss://r.example".to_string()], None)
        );
    }

    #[test]
    fn bunker_uri_refuses_the_unusable() {
        let pk = Keys::generate().public_key().to_hex();
        for bad in [
            "".to_string(),
            "nostrconnect://x?relay=wss://r".to_string(),
            format!("https://{pk}?relay=wss://r.example"),
            "bunker://nothex?relay=wss://r.example".to_string(),
            format!("bunker://{pk}"),
            format!("bunker://{pk}?relay=ws://r.example"),
            format!("bunker://{pk}?relay=https://r.example"),
            format!(
                "bunker://{pk}?relay=wss://r.example&secret={}",
                "x".repeat(300)
            ),
        ] {
            assert!(
                matches!(parse_bunker_uri(&bad), Err(Error::Uri(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn check_signed_rejects_substitutions() {
        let persona = Keys::generate();
        let asked = EventBuilder::new(Kind::Custom(30420), "")
            .tag(Tag::identifier("x"))
            .build(persona.public_key());
        let good = asked.clone().sign_with_keys(&persona).unwrap();
        assert!(check_signed(&good, &asked, &persona.public_key()).is_ok());
        let other = Keys::generate();
        let by_other = EventBuilder::new(Kind::Custom(30420), "")
            .tag(Tag::identifier("x"))
            .sign_with_keys(&other)
            .unwrap();
        assert!(check_signed(&by_other, &asked, &persona.public_key()).is_err());
        let changed = EventBuilder::new(Kind::Custom(30420), "")
            .tag(Tag::identifier("y"))
            .sign_with_keys(&persona)
            .unwrap();
        assert!(check_signed(&changed, &asked, &persona.public_key()).is_err());
    }
}
