//! Sign in with Signet: My Signet's `?auth=1` relay-mode sign-in, the
//! consumer side (section 5.1 of the game's spec). Ported from an earlier Kotlin implementation,
//! whose checks follow signet-verify's `waitForAuthResponse` one for one.
//!
//! The `nostrconnect://` pairing proves who signs, but nothing on it carries
//! the persona's name. This flow returns, from one approval, the persona
//! pubkey (proven by a signed challenge), the persona's handle when the person
//! chooses to share it, and a `bunker://` URI to sign with.
//!
//! The answer comes back over a relay, gift-wrapped (NIP-59) to a throwaway
//! session key that lives only in [`Request`]: never persisted, never the
//! NIP-46 transport key. Nothing here names a game: the origin, the app name
//! and the relay all come from [`crate::SignetConfig`].

use base64::Engine;
use nostr::nips::nip44;
use nostr::util::JsonUtil;
use nostr::{Event, Keys, Kind, PublicKey, Timestamp, UnsignedEvent, Url};
use serde_json::Value;

use crate::contacts_wire::sanitize_wire_text;

/// The rumor kind My Signet answers with, approval or denial.
pub const RESPONSE_KIND: u16 = 29999;
/// The signed challenge inside an approval.
pub const AUTH_EVENT_KIND: u16 = 21236;
/// signet-verify's `AUTH_FRESHNESS_WINDOW_SEC`: the answer and its auth event
/// are each this fresh, in either direction.
pub const FRESHNESS_SECS: u64 = 300;
/// How far before the request the subscription's `since` reaches. My Signet
/// backdates its wrap by up to 30 s, and phone clocks disagree.
pub const SINCE_SLACK_SECS: u64 = 60;
/// signet-verify's cap on a persona's handle.
pub const NAME_MAX_CHARS: usize = 64;
/// Largest gift wrap we try to open.
pub(crate) const MAX_WRAP_CONTENT: usize = 64 * 1024;

/// Where the request goes.
const MY_SIGNET: &str = "https://mysignet.app/";

/// The reason a sign-in ends when the person taps Deny in My Signet.
pub const DECLINED: &str = "You declined in My Signet. Try again when you're ready.";
/// The signer behind the `bunker://` answered as someone other than the
/// persona that signed the challenge.
pub const WRONG_PROFILE: &str =
    "My Signet's signer answered as a different persona, so nobody was signed in.";
/// My Signet sent a signer link (`bunkerUri`) that this app cannot use.
pub const BAD_BUNKER: &str = "My Signet's signer link couldn't be used, so nobody was signed in. Try signing in another way.";
/// The relay closed the subscription: no answer can ever reach this attempt.
pub const RELAY_REFUSED: &str =
    "The relay wouldn't pass on My Signet's answer. Try again, or sign in another way.";
/// The headline when every candidate relay failed to open: neutral on
/// purpose, since a list of what each one did follows it.
pub const ALL_RELAYS_FAILED: &str = "No relay would carry the sign-in";
/// No origin is configured, or it is not a bare `https://host`.
pub const NO_ORIGIN: &str = "Sign in with Signet isn't set up for this app.";
/// No relay to listen on.
pub const NO_RELAY: &str = "No relay to sign in over.";
/// What `refresh_attestation` says for a persona that signed in without a bunker.
pub const NO_SIGNER: &str =
    "This persona can't sign for this app from My Signet, so there is nothing to confirm.";

/// What `pair_contacts` says for a persona that signed in without a bunker.
pub const NO_SIGNER_CONTACTS: &str =
    "Contacts need a bunker from My Signet, which this persona doesn't have.";

/// A fresh attempt: new challenge, new session key, nothing reused.
pub struct Request {
    /// 32 random bytes, lowercase hex. Doubles as the request id.
    pub(crate) challenge: String,
    /// Opens the answer. Exists nowhere else.
    pub(crate) session: Keys,
    pub(crate) issued_at: u64,
    pub(crate) relay: String,
    origin: String,
    app_name: String,
    online_play: Option<(String, PublicKey)>,
}

impl Request {
    /// `origin` must be a bare `https://host[:port]` (no path, no trailing
    /// slash): it is compared to the auth event's `origin` tag as a string.
    pub fn new(
        origin: &str,
        app_name: &str,
        relay: &str,
        now: u64,
    ) -> Result<Request, &'static str> {
        if !is_bare_https_origin(origin) {
            return Err(NO_ORIGIN);
        }
        let relay = relay.trim().trim_end_matches('/');
        if relay.is_empty()
            || Url::parse(relay).is_err()
            || !relay.to_ascii_lowercase().starts_with("wss://")
        {
            return Err(NO_RELAY);
        }
        let mut c = [0u8; 32];
        getrandom::fill(&mut c).map_err(|_| NO_RELAY)?;
        Ok(Request {
            challenge: hex::encode(c),
            session: Keys::generate(),
            issued_at: now,
            relay: relay.to_string(),
            origin: origin.to_string(),
            app_name: app_name.chars().take(NAME_MAX_CHARS).collect(),
            online_play: None,
        })
    }

    /// Request a bounded game statement alongside sign-in. Older signers ignore
    /// the extension; their normal sign-in answer remains valid.
    pub fn with_online_play(mut self, app_id: &str, runtime: PublicKey) -> Self {
        self.online_play = Some((app_id.to_owned(), runtime));
        self
    }

    pub fn session_pubkey(&self) -> PublicKey {
        self.session.public_key()
    }

    /// `https://mysignet.app/?auth=1&challenge=…&origin=…&name=…&callback=…&t=…&relay=…&sessionPubkey=…`
    ///
    /// `callback` is required by My Signet's parser (https, same origin as
    /// `origin`) but unused in relay mode; nothing is hosted there.
    pub fn url(&self) -> String {
        let mut url = Url::parse(MY_SIGNET).expect("static URL");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("auth", "1");
            q.append_pair("challenge", &self.challenge);
            q.append_pair("origin", &self.origin);
            q.append_pair("name", &self.app_name);
            q.append_pair("callback", &format!("{}/signet", self.origin));
            q.append_pair("t", &self.issued_at.to_string());
            q.append_pair("relay", &self.relay);
            q.append_pair("sessionPubkey", &self.session.public_key().to_hex());
            if let Some((app_id, runtime)) = &self.online_play {
                let request = serde_json::json!({
                    "v": 1, "permission": "online-play", "appId": app_id,
                    "installKey": runtime.to_hex(), "validFrom": self.issued_at,
                    "validUntil": self.issued_at + crate::attestation::VALIDITY_SECS,
                    "reason": format!("{} shows other players in a game that it is really you.", self.app_name),
                });
                q.append_pair(
                    "app_permission",
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request.to_string()),
                );
            }
        }
        url.to_string()
    }

    /// What to subscribe to: gift wraps addressed to the session key.
    pub fn filter(&self) -> nostr::Filter {
        nostr::Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(self.session.public_key())
            .since(Timestamp::from(
                self.issued_at.saturating_sub(SINCE_SLACK_SECS),
            ))
    }
}

/// Never prints the challenge: a log line must not be enough to forge a denial.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Request(issued_at={})", self.issued_at)
    }
}

pub(crate) fn is_bare_https_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty()
        && !rest.contains(['/', '?', '#', '@', ' '])
        && Url::parse(origin).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some())
}

#[derive(Clone, PartialEq, Eq)]
pub enum OnlinePlayResult {
    Approved(Box<Event>),
    Declined,
}

/// What one gift wrap on the sign-in subscription turned out to be.
#[derive(Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A valid approval from `persona`.
    Approved {
        persona: PublicKey,
        /// The persona's handle, if the person shared it. Cleaned and capped.
        display_name: Option<String>,
        /// The `bunkerUri` My Signet sent, trimmed; `None` when it sent none
        /// (a direct-child persona gets none). It is **not** parsed here: one
        /// that is present but unusable fails the sign-in
        /// ([`BAD_BUNKER`]), it does not turn into "no bunker".
        bunker_uri: Option<String>,
        online_play: Option<OnlinePlayResult>,
    },
    /// The person tapped Deny.
    Declined,
    /// Not an answer to this request, or not a valid one. The reason is
    /// static text, never content.
    Dropped(&'static str),
}

/// The name and the bunker secret stay out of any log line.
impl std::fmt::Debug for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Approved {
                display_name,
                bunker_uri,
                ..
            } => write!(
                f,
                "Approved(has_name={}, has_bunker={})",
                display_name.is_some(),
                bunker_uri.is_some()
            ),
            Verdict::Declined => f.write_str("Declined"),
            Verdict::Dropped(r) => write!(f, "Dropped({r})"),
        }
    }
}

/// Open a NIP-59 wrap addressed to the session key: the wrap's and the
/// seal's id and signature, an untagged kind 13 seal, and a rumor authored by
/// the seal's signer. Returns the rumor and the seal's signer.
pub(crate) fn unwrap_for(session: &Keys, wrap: &Event) -> Option<(UnsignedEvent, PublicKey)> {
    if wrap.kind != Kind::GiftWrap
        || wrap.content.len() > MAX_WRAP_CONTENT
        || wrap.verify().is_err()
    {
        return None;
    }
    let addressed = wrap.tags.iter().any(|t| {
        let s = t.as_slice();
        s.len() >= 2 && s[0] == "p" && s[1] == session.public_key().to_hex()
    });
    if !addressed {
        return None;
    }
    let seal_json = nip44::decrypt(session.secret_key(), &wrap.pubkey, &wrap.content).ok()?;
    let seal = Event::from_json(seal_json).ok()?;
    if seal.kind != Kind::Seal
        || !seal.tags.is_empty()
        || seal.content.len() > MAX_WRAP_CONTENT
        || seal.verify().is_err()
    {
        return None;
    }
    let rumor_json = nip44::decrypt(session.secret_key(), &seal.pubkey, &seal.content).ok()?;
    let rumor = UnsignedEvent::from_json(rumor_json).ok()?;
    if rumor.pubkey != seal.pubkey {
        return None;
    }
    Some((rumor, seal.pubkey))
}

pub(crate) fn tag_value<'a>(
    tags: impl Iterator<Item = &'a [String]>,
    name: &str,
) -> Option<&'a str> {
    for t in tags {
        if t.len() >= 2 && t[0] == name {
            return Some(t[1].as_str());
        }
    }
    None
}

pub(crate) fn json_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// signet-verify's `sanitiseDisplayName`: drop control and invisible /
/// direction-changing characters, trim, cap at [`NAME_MAX_CHARS`]. Empty is absent.
/// For display it also drops what the hello's name sanitiser does (U+061C,
/// U+2060-2069, U+FEFF inside the name).
pub fn clean_shared_name(raw: &str) -> Option<String> {
    let s: String = sanitize_wire_text(raw, NAME_MAX_CHARS)
        .chars()
        .filter(|c| !crate::hidden_char(*c))
        .collect();
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Judge one gift wrap against `req`, every check in the spec's order; the first that
/// fails drops the event.
pub fn judge(req: &Request, wrap: &Event, now: u64) -> Verdict {
    use Verdict::Dropped;
    // 1. Unwrap with the session key.
    let Some((rumor, seal_author)) = unwrap_for(&req.session, wrap) else {
        return Dropped("gift wrap did not open");
    };
    // 2. A Signet answer, to this challenge.
    if rumor.kind != Kind::Custom(RESPONSE_KIND) {
        return Dropped("wrong rumor kind");
    }
    let tags = || rumor.tags.iter().map(|t| t.as_slice());
    let Some(session) = tag_value(tags(), "session") else {
        return Dropped("no session tag");
    };
    if session.to_ascii_lowercase() != req.challenge {
        return Dropped("another session");
    }
    let Some(status) = tag_value(tags(), "status") else {
        return Dropped("no status tag");
    };
    // 3. A denial for this challenge ends the attempt, naming nobody.
    if status == "rejected" {
        return Verdict::Declined;
    }
    // 4. An approval, for this request.
    if status != "approved" {
        return Dropped("unknown status");
    }
    if rumor.content.len() > MAX_WRAP_CONTENT {
        return Dropped("content too large");
    }
    let Ok(content) = serde_json::from_str::<Value>(&rumor.content) else {
        return Dropped("content is not JSON");
    };
    if !content.is_object() {
        return Dropped("content is not a JSON object");
    }
    if json_str(&content, "type") != Some("signet-auth-response") {
        return Dropped("not an auth response");
    }
    if json_str(&content, "requestId")
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some(req.challenge.as_str())
    {
        return Dropped("wrong request id");
    }
    // 5. The signed challenge.
    let Some(auth_json) = content.get("authEvent").filter(|v| v.is_object()) else {
        return Dropped("no auth event");
    };
    let Ok(auth) = serde_json::from_value::<Event>(auth_json.clone()) else {
        return Dropped("malformed auth event");
    };
    if auth.kind != Kind::Custom(AUTH_EVENT_KIND) {
        return Dropped("wrong auth event kind");
    }
    // Recomputes the id from the contents, then checks the Schnorr signature.
    if auth.verify().is_err() {
        return Dropped("auth event signature does not check out");
    }
    let atags = || auth.tags.iter().map(|t| t.as_slice());
    if tag_value(atags(), "challenge")
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some(req.challenge.as_str())
    {
        return Dropped("auth event for another challenge");
    }
    if tag_value(atags(), "origin") != Some(req.origin.as_str()) {
        return Dropped("auth event for another origin");
    }
    if auth.created_at.as_secs().abs_diff(now) > FRESHNESS_SECS {
        return Dropped("auth event is stale");
    }
    // 6. The persona that signed the challenge also sealed the answer.
    if auth.pubkey != seal_author {
        return Dropped("auth event and seal signed by different keys");
    }
    // 7. The answer itself is fresh: a relay may serve an old one.
    if rumor.created_at.as_secs().abs_diff(now) > FRESHNESS_SECS {
        return Dropped("answer is stale");
    }
    // 8. The name, cleaned for display. Optional: the person may not share it.
    let display_name = json_str(&content, "displayName").and_then(clean_shared_name);
    // 9. The bunker to sign with. Absence (missing, null or blank) is not a
    //    fault: the caller signs the person in without an attestation. A
    //    value that is there is kept as sent; the caller parses it and fails
    //    the sign-in when it is unusable (never "no bunker" by accident).
    let bunker_uri = match content.get("bunkerUri") {
        None | Some(Value::Null) => None,
        Some(Value::String(u)) => Some(u.trim().to_string()).filter(|u| !u.is_empty()),
        // Present, but not even text: unusable.
        Some(_) => Some("?".to_string()),
    };
    let online_play = match content.get("appPermission") {
        None => None, // A signer that predates this optional extension.
        Some(value) => {
            let Some((app_id, runtime)) = &req.online_play else {
                return Dropped("unsolicited online permission");
            };
            if value.get("v") != Some(&serde_json::json!(1))
                || value.get("permission").and_then(Value::as_str) != Some("online-play")
            {
                return Dropped("invalid online permission response");
            }
            match value.get("status").and_then(Value::as_str) {
                Some("declined") if value.get("event").is_none() => {
                    Some(OnlinePlayResult::Declined)
                }
                Some("approved") => {
                    let Some(event) = value
                        .get("event")
                        .and_then(|v| serde_json::from_value::<Event>(v.clone()).ok())
                    else {
                        return Dropped("missing online statement");
                    };
                    let expected = crate::attestation::unsigned_attestation(
                        app_id,
                        &auth.pubkey,
                        runtime,
                        req.issued_at,
                    );
                    if event.pubkey != auth.pubkey
                        || event.content != expected.content
                        || event.tags != expected.tags
                        || event.created_at.as_secs().abs_diff(now) > FRESHNESS_SECS
                        || crate::attestation::verify_attestation_event(
                            app_id, &event, runtime, now,
                        )
                        .is_err()
                    {
                        return Dropped("online statement does not match sign-in");
                    }
                    Some(OnlinePlayResult::Approved(Box::new(event)))
                }
                _ => return Dropped("invalid online permission outcome"),
            }
        }
    };
    Verdict::Approved {
        persona: auth.pubkey,
        display_name,
        bunker_uri,
        online_play,
    }
}

// ─── Which relay carries the answer ─────────────────────────────────────────

/// How long one candidate relay gets to confirm the sign-in subscription
/// (EOSE, or at least connected with no CLOSED and no error) before the link
/// goes out on it, or the next candidate is tried.
pub const OPEN_WAIT: std::time::Duration = std::time::Duration::from_secs(4);

/// The relays a sign-in tries, in order: `defaults` first, in their own order,
/// then any other relay of the player's, in their order. Compared (and
/// returned) as [`decented_relays::normalize_relay_url`] writes them, so a
/// trailing slash or capitals don't make a second relay. Only `wss://` relays
/// are kept: the request link refuses anything else.
pub fn relay_order(defaults: &[String], others: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in defaults.iter().chain(others) {
        let n = decented_relays::normalize_relay_url(u);
        if n.starts_with("wss://") && Url::parse(&n).is_ok() && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

/// The host of a relay URL, for the screen and the log.
pub fn relay_host(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| {
            url.trim_start_matches("wss://")
                .trim_end_matches('/')
                .to_string()
        })
}

/// Why one relay could not carry a sign-in, as short as the screen needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayFailure {
    /// The socket could not be opened (no route, refused, DNS, TLS).
    Connect,
    /// The relay answered the upgrade with this HTTP status (a 503 is the
    /// usual way a public relay says it is overloaded).
    Http(u16),
    /// It did not finish connecting in time.
    Timeout,
    /// It answered, and CLOSED the subscription.
    Closed,
    /// It was connected, and the connection went away.
    Dropped,
}

impl RelayFailure {
    /// From the relay layer's reason for a failed or dropped connection
    /// ([`crate::relay::SubStatus::Down`]).
    pub fn from_down(reason: &str) -> RelayFailure {
        if let Some(i) = reason.find("HTTP error: ") {
            let digits: String = reason[i + 12..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if let Ok(code) = digits.parse() {
                return RelayFailure::Http(code);
            }
        }
        if reason.contains("timed out") {
            RelayFailure::Timeout
        } else {
            RelayFailure::Connect
        }
    }

    /// The words for the per-relay list.
    pub fn phrase(&self) -> String {
        match self {
            RelayFailure::Connect => "couldn't connect".into(),
            RelayFailure::Http(c) if *c >= 500 => format!("unavailable ({c})"),
            RelayFailure::Http(c) => format!("refused ({c})"),
            RelayFailure::Timeout => "timed out".into(),
            RelayFailure::Closed => "closed the request".into(),
            RelayFailure::Dropped => "dropped the connection".into(),
        }
    }
}

/// One relay a sign-in tried, by host, and how it failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAttempt {
    pub host: String,
    pub failure: RelayFailure,
}

/// "relay.example.com: couldn't connect · relay.damus.io: unavailable (503)".
pub fn failure_summary(tried: &[RelayAttempt]) -> String {
    tried
        .iter()
        .map(|a| format!("{}: {}", a.host, a.failure.phrase()))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Every candidate failed: the neutral headline, then one line listing each
/// relay with its reason.
pub fn all_failed(tried: &[RelayAttempt]) -> String {
    format!("{ALL_RELAYS_FAILED}\n{}", failure_summary(tried))
}

/// The relay CLOSED the subscription after the link went out: no answer can
/// reach this attempt.
pub fn relay_closed(host: &str) -> String {
    format!(
        "{host} closed the sign-in request, so My Signet's answer can't reach this app. Try again, or sign in another way."
    )
}

/// Nothing arrived in time. `down` is the last connection trouble on the
/// relay (if it has not recovered).
pub fn no_answer(base: &str, host: &str, down: Option<&RelayFailure>) -> String {
    match down {
        None => format!("{base} It was listening on {host}."),
        Some(f) => format!(
            "{base} It was listening on {host}, which {}.",
            f.phrase_after_link()
        ),
    }
}

impl RelayFailure {
    /// Mid-attempt wording: a lost connection isn't "couldn't connect".
    fn phrase_after_link(&self) -> String {
        match self {
            RelayFailure::Connect | RelayFailure::Dropped => "dropped the connection".into(),
            other => format!("is now {}", other.phrase()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_url_carries_every_parameter_and_is_fresh_each_time() {
        let a = Request::new(
            "https://decented.org",
            "Twang Thang",
            "wss://relay.test/",
            1_000,
        )
        .unwrap();
        let b = Request::new(
            "https://decented.org",
            "Twang Thang",
            "wss://relay.test",
            1_000,
        )
        .unwrap();
        assert_ne!(a.challenge, b.challenge);
        assert_ne!(a.session_pubkey(), b.session_pubkey());
        assert_eq!(a.challenge.len(), 64);
        let u = Url::parse(&a.url()).unwrap();
        assert_eq!(u.host_str(), Some("mysignet.app"));
        let q: std::collections::HashMap<_, _> = u
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(q["auth"], "1");
        assert_eq!(q["challenge"], a.challenge);
        assert_eq!(q["origin"], "https://decented.org");
        assert_eq!(q["name"], "Twang Thang");
        assert_eq!(q["callback"], "https://decented.org/signet");
        assert_eq!(q["t"], "1000");
        assert_eq!(q["relay"], "wss://relay.test");
        assert_eq!(q["sessionPubkey"], a.session_pubkey().to_hex());
        assert!(!format!("{a:?}").contains(&a.challenge));
    }

    #[test]
    fn only_a_bare_https_origin_and_a_wss_relay_are_accepted() {
        for bad in [
            "",
            "http://decented.org",
            "https://decented.org/",
            "https://decented.org/x",
            "decented.org",
            "https://",
        ] {
            assert_eq!(
                Request::new(bad, "x", "wss://r.test", 1).err(),
                Some(NO_ORIGIN),
                "{bad}"
            );
        }
        for bad in ["", "ws://r.test", "https://r.test", "nonsense"] {
            assert_eq!(
                Request::new("https://decented.org", "x", bad, 1).err(),
                Some(NO_RELAY),
                "{bad}"
            );
        }
    }

    #[test]
    fn names_are_cleaned_and_capped() {
        assert_eq!(clean_shared_name("  Ada  ").as_deref(), Some("Ada"));
        assert_eq!(
            clean_shared_name("A\u{202e}da\u{200b}\n").as_deref(),
            Some("Ada")
        );
        assert_eq!(clean_shared_name("   "), None);
        assert_eq!(
            clean_shared_name(&"x".repeat(200)).unwrap().chars().count(),
            NAME_MAX_CHARS
        );
        // What the hello's name sanitiser drops goes too.
        assert_eq!(
            clean_shared_name("Mu\u{2060}m\u{061C}\u{FEFF}s").as_deref(),
            Some("Mums")
        );
        assert_eq!(clean_shared_name("\u{2061}\u{2062}\u{2064}"), None);
    }

    #[test]
    fn the_relay_order_puts_defaults_first_then_the_players_own_without_repeats() {
        let defaults: Vec<String> = [
            "wss://relay.example.com",
            "wss://relay.damus.io",
            "wss://nos.lol",
        ]
        .map(String::from)
        .to_vec();
        let mine: Vec<String> = [
            "wss://relay.primal.net",
            "WSS://NOS.LOL/",
            "wss://relay.damus.io:443",
            "ws://plain.test",
            "wss://relay.primal.net/",
            "wss://my.relay/nostr",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            relay_order(&defaults, &mine),
            [
                "wss://relay.example.com",
                "wss://relay.damus.io",
                "wss://nos.lol",
                "wss://relay.primal.net",
                "wss://my.relay/nostr"
            ]
        );
        assert!(relay_order(&[], &[]).is_empty());
        assert_eq!(relay_order(&[], &mine)[0], "wss://relay.primal.net");
    }

    #[test]
    fn relay_failures_read_as_short_phrases() {
        assert_eq!(
            RelayFailure::from_down("HTTP error: 503 Service Unavailable"),
            RelayFailure::Http(503)
        );
        assert_eq!(RelayFailure::from_down("timed out"), RelayFailure::Timeout);
        assert_eq!(
            RelayFailure::from_down("IO error: Connection refused"),
            RelayFailure::Connect
        );
        let tried = [
            RelayAttempt {
                host: "relay.example.com".into(),
                failure: RelayFailure::Connect,
            },
            RelayAttempt {
                host: "relay.damus.io".into(),
                failure: RelayFailure::Http(503),
            },
        ];
        assert_eq!(
            failure_summary(&tried),
            "relay.example.com: couldn't connect · relay.damus.io: unavailable (503)"
        );
        assert_eq!(relay_host("wss://relay.damus.io/x"), "relay.damus.io");
    }
}
