//! "Ask My Signet to play online": My Signet's `?action=app-permission`
//! request with `permission=online-play`, the consumer side.
//!
//! A persona signed in by Sign in with Signet with no bunker has nothing that
//! can sign the runtime-key attestation (kind 30420). This asks My Signet to
//! sign exactly one fixed statement, the attestation template this module
//! sends, and waits for the answer: a stored NIP-59 gift wrap to a throwaway
//! session key on the relay the link names. For a child's persona the
//! guardian approves on their own phone; an adult approves for themselves.
//!
//! The wire contract is My Signet's `src/lib/app-permission.ts`: the request
//! parser (`parseAppPermissionRequest`), the one template shape
//! (`validateAppPermissionTemplate`) and the answer rumors. Every rule the
//! parser applies is checked here before a link is built, so a request this
//! module makes is never refused for its form. Text over a cap is refused,
//! never cut.
//!
//! The session key lives only in [`PermissionRequest`]: never persisted.
//! Nothing here names a game: the origin, the name, the reason and the app id
//! all come from [`crate::SignetConfig`] and the template.

use base64::Engine;
use nostr::util::JsonUtil;
use nostr::{Event, Keys, Kind, PublicKey, Timestamp, UnsignedEvent, Url};
use serde_json::{Value, json};

use super::signin::{
    self, RelayAttempt, SINCE_SLACK_SECS, failure_summary, is_bare_https_origin, json_str,
    tag_value, unwrap_for,
};
use crate::attestation::{
    ATTESTATION_KIND, ATTESTATION_VERSION, MAX_ATTESTATION_LEN, PLAYER_ROLE,
    verify_attestation_event,
};
use crate::contacts_wire::sanitize_wire_text;

/// `?action=` of the request.
pub const ACTION: &str = "app-permission";
/// The one permission v1 asks for.
pub const PERMISSION: &str = "online-play";
/// `type` of the answer's content.
pub const RESPONSE_TYPE: &str = "signet-app-permission-response";
/// The answer rumor's kind, approval or denial (as for `?auth=1`).
pub const RESPONSE_KIND: u16 = signin::RESPONSE_KIND;
/// `t` and the template's `valid_from` must be this close to My Signet's
/// clock when it parses the link.
pub const FRESHNESS_SECS: u64 = 300;
/// The longest a statement may last.
pub const MAX_VALIDITY_SECS: u64 = 90 * 86_400;
/// The parser's caps, in code points (name, reason) and characters (the
/// base64url `template` param, the relay URL).
pub const NAME_MAX: usize = 64;
pub const REASON_MAX: usize = 200;
pub const TEMPLATE_PARAM_MAX: usize = 4096;
pub const RELAY_MAX: usize = 1024;
/// How long an ask waits for an answer. My Signet holds a child's ask for
/// 600 s; a minute more covers the relay and the clocks. There is no waiting
/// across launches in v1.
pub const PERMISSION_WAIT_SECS: u64 = 660;
/// The largest answer content opened. An approval is a short JSON object and
/// one attestation event.
const MAX_ANSWER_CONTENT: usize = 8 * 1024;

/// Where the request goes.
const MY_SIGNET: &str = "https://mysignet.app/";

/// Asked while signed out.
pub const NOT_SIGNED_IN: &str = "Sign in with My Signet first.";
/// The app gave no reason, or one that is empty or too long once cleaned.
pub const BAD_REASON: &str = "Asking My Signet for online play isn't set up for this app.";
/// The app's name is empty or too long once cleaned.
pub const BAD_NAME: &str = "This app's name can't be shown in My Signet.";
/// The statement to sign is not the one shape My Signet signs.
pub const BAD_TEMPLATE: &str = "The statement for My Signet to sign isn't in the form it accepts.";
/// The encoded statement is over [`TEMPLATE_PARAM_MAX`].
pub const TEMPLATE_TOO_LARGE: &str = "The statement for My Signet to sign is too large to send.";
/// The headline when every candidate relay failed to open.
pub const ALL_RELAYS_FAILED: &str = "No relay would carry the request to My Signet";
/// The answer arrived after a sign-out, or for a persona no longer signed in.
pub const SIGNED_OUT_WHILE_WAITING: &str =
    "The persona changed while waiting, so the answer wasn't kept.";
/// A newer ask replaced this one.
pub const SUPERSEDED: &str = "A newer request replaced this one.";

/// Every candidate failed: the headline, then one line listing each relay.
pub fn all_failed(tried: &[RelayAttempt]) -> String {
    format!("{ALL_RELAYS_FAILED}\n{}", failure_summary(tried))
}

/// The relay CLOSED the subscription after the link went out.
pub fn relay_closed(host: &str) -> String {
    format!("{host} closed the request, so My Signet's answer can't reach this app. Try again.")
}

/// Unicode format characters (General Category Cf) and U+180E, which the
/// parser strips after its shared sanitiser (`FORMAT_CHARS` in
/// `app-permission.ts`). Unicode 15.1.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00ad}'
        | '\u{0600}'..='\u{0605}'
        | '\u{061c}'
        | '\u{06dd}'
        | '\u{070f}'
        | '\u{0890}'..='\u{0891}'
        | '\u{08e2}'
        | '\u{180e}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}'
        | '\u{feff}'
        | '\u{fff9}'..='\u{fffb}'
        | '\u{110bd}'
        | '\u{110cd}'
        | '\u{13430}'..='\u{1343f}'
        | '\u{1bca0}'..='\u{1bca3}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{e0001}'
        | '\u{e0020}'..='\u{e007f}')
}

/// The parser's `boundedText`: the shared sanitiser **uncapped**, then the
/// format characters stripped, trimmed, and 1..=`max` code points. Over-long
/// text is refused (`None`), never cut.
pub fn bounded_text(raw: &str, max: usize) -> Option<String> {
    let s = sanitize_wire_text(raw, usize::MAX);
    let s: String = s.chars().filter(|c| !is_format_char(*c)).collect();
    let s = s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    let n = s.chars().count();
    (1..=max).contains(&n).then(|| s.to_string())
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 64 lowercase hex that is an x-only secp256k1 point.
fn is_point(s: &str) -> bool {
    is_lower_hex64(s) && PublicKey::from_hex(s).is_ok()
}

/// The parser's `uint`: no sign, no leading zero, at most 16 digits.
fn uint(s: &str) -> Option<u64> {
    let ok = !s.is_empty()
        && s.len() <= 16
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    ok.then(|| s.parse().ok()).flatten()
}

/// The template's tag names, in the order the attestation builds them.
const TAG_NAMES: [&str; 7] = [
    "d",
    "p",
    "valid_from",
    "valid_until",
    "v",
    "role",
    "expiration",
];

/// The JSON the link carries: exactly `{kind, pubkey, content, tags}` of the
/// unsigned attestation (no `created_at`, no `id`; My Signet sets those).
fn template_json(t: &UnsignedEvent) -> Value {
    let tags: Vec<Vec<String>> = t.tags.iter().map(|tag| tag.as_slice().to_vec()).collect();
    json!({
        "kind": t.kind.as_u16(),
        "pubkey": t.pubkey.to_hex(),
        "content": t.content,
        "tags": tags,
    })
}

/// What a valid template says.
struct TemplateDetails {
    app_id: String,
    runtime: PublicKey,
}

/// `validateAppPermissionTemplate` with the clock check, as the parser runs it.
fn check_template(t: &UnsignedEvent, now: u64) -> Option<TemplateDetails> {
    if t.kind != Kind::Custom(ATTESTATION_KIND) || !t.content.is_empty() {
        return None;
    }
    let pubkey = t.pubkey.to_hex();
    let tags: Vec<&[String]> = t.tags.iter().map(|x| x.as_slice()).collect();
    if tags.len() != TAG_NAMES.len() {
        return None;
    }
    let mut seen: Vec<&str> = Vec::new();
    for tag in &tags {
        if tag.len() != 2
            || !TAG_NAMES.contains(&tag[0].as_str())
            || seen.contains(&tag[0].as_str())
        {
            return None;
        }
        seen.push(tag[0].as_str());
    }
    let v = |name: &str| tag_value(tags.iter().copied(), name).unwrap_or_default();
    let d = v("d");
    let id_ok = (1..=64).contains(&d.len())
        && d.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !id_ok || !is_point(v("p")) || v("p") == pubkey {
        return None;
    }
    let from = uint(v("valid_from"))?;
    if from.abs_diff(now) > FRESHNESS_SECS {
        return None;
    }
    let until = uint(v("valid_until"))?;
    if until <= from || until > from.saturating_add(MAX_VALIDITY_SECS) {
        return None;
    }
    if v("v") != ATTESTATION_VERSION
        || v("role") != PLAYER_ROLE
        || v("expiration") != v("valid_until")
    {
        return None;
    }
    Some(TemplateDetails {
        app_id: d.to_string(),
        runtime: PublicKey::from_hex(v("p")).ok()?,
    })
}

/// One ask: a fresh challenge and session key, nothing reused.
pub struct PermissionRequest {
    /// 32 random bytes, lowercase hex.
    pub(crate) challenge: String,
    /// Opens the answer. Exists nowhere else.
    pub(crate) session: Keys,
    pub(crate) issued_at: u64,
    pub(crate) relay: String,
    origin: String,
    name: String,
    reason: String,
    /// `{kind, pubkey, content, tags}` as sent: the approval must match it.
    template: Value,
    /// The `template=` param (base64url, no padding).
    template_param: String,
    app_id: String,
    runtime: PublicKey,
}

impl PermissionRequest {
    /// Check every rule My Signet's parser applies, then build. `origin` must
    /// be a bare `https://host`; `relay` a `wss://` URL. `name` and `reason`
    /// are cleaned the way the parser cleans them and refused (not cut) when
    /// empty or over [`NAME_MAX`] / [`REASON_MAX`]. `template` is the unsigned
    /// attestation ([`crate::attestation::unsigned_attestation`]); its
    /// `created_at` is not sent.
    pub fn new(
        origin: &str,
        name: &str,
        reason: &str,
        template: &UnsignedEvent,
        relay: &str,
        now: u64,
    ) -> Result<PermissionRequest, &'static str> {
        if !is_bare_https_origin(origin) {
            return Err(signin::NO_ORIGIN);
        }
        let name = bounded_text(name, NAME_MAX).ok_or(BAD_NAME)?;
        let reason = bounded_text(reason, REASON_MAX).ok_or(BAD_REASON)?;
        let relay = relay.trim().trim_end_matches('/');
        if relay.is_empty()
            || relay.len() > RELAY_MAX
            || Url::parse(relay).is_err()
            || !relay.to_ascii_lowercase().starts_with("wss://")
        {
            return Err(signin::NO_RELAY);
        }
        let json = template_json(template);
        let template_param =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.to_string());
        if template_param.len() > TEMPLATE_PARAM_MAX {
            return Err(TEMPLATE_TOO_LARGE);
        }
        let details = check_template(template, now).ok_or(BAD_TEMPLATE)?;
        let template = json;
        let mut c = [0u8; 32];
        getrandom::fill(&mut c).map_err(|_| signin::NO_RELAY)?;
        Ok(PermissionRequest {
            challenge: hex::encode(c),
            session: Keys::generate(),
            issued_at: now,
            relay: relay.to_string(),
            origin: origin.to_string(),
            name,
            reason,
            template,
            template_param,
            app_id: details.app_id,
            runtime: details.runtime,
        })
    }

    pub fn session_pubkey(&self) -> PublicKey {
        self.session.public_key()
    }

    /// The relay the link names.
    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// `https://mysignet.app/?action=app-permission&permission=online-play&origin=…&name=…
    /// &reason=…&template=…&relay=…&sessionPubkey=…&challenge=…&t=…&callback=…`
    ///
    /// `callback` is required by the parser (same origin as `origin`) and
    /// unused in relay mode; nothing is hosted there.
    pub fn url(&self) -> String {
        let mut url = Url::parse(MY_SIGNET).expect("static URL");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("action", ACTION);
            q.append_pair("permission", PERMISSION);
            q.append_pair("origin", &self.origin);
            q.append_pair("name", &self.name);
            q.append_pair("reason", &self.reason);
            q.append_pair("template", &self.template_param);
            q.append_pair("relay", &self.relay);
            q.append_pair("sessionPubkey", &self.session.public_key().to_hex());
            q.append_pair("challenge", &self.challenge);
            q.append_pair("t", &self.issued_at.to_string());
            q.append_pair("callback", &format!("{}/signet", self.origin));
        }
        url.to_string()
    }

    /// Stored gift wraps to the session key, from a minute before the request.
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
impl std::fmt::Debug for PermissionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PermissionRequest(issued_at={})", self.issued_at)
    }
}

/// What one gift wrap on the ask's subscription turned out to be.
#[derive(Clone, PartialEq, Eq)]
pub enum PermissionVerdict {
    /// The template, signed by the persona: a valid attestation for this
    /// app and this runtime key.
    Approved(Box<Event>),
    /// Deny (guardian) or Cancel (the person). From any signer: a forged
    /// denial only ends the attempt.
    Denied,
    /// Not an answer to this ask, or not a valid one. Static text, never content.
    Dropped(&'static str),
}

/// The signed statement stays out of log lines.
impl std::fmt::Debug for PermissionVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionVerdict::Approved(_) => f.write_str("Approved"),
            PermissionVerdict::Denied => f.write_str("Denied"),
            PermissionVerdict::Dropped(r) => write!(f, "Dropped({r})"),
        }
    }
}

/// The tags of an event as plain string lists.
fn tag_lists(ev: &Event) -> Value {
    Value::from(
        ev.tags
            .iter()
            .map(|t| Value::from(t.as_slice().to_vec()))
            .collect::<Vec<_>>(),
    )
}

/// Judge one gift wrap against `req`; the first check that fails drops it.
pub fn judge(req: &PermissionRequest, wrap: &Event, now: u64) -> PermissionVerdict {
    use PermissionVerdict::{Denied, Dropped};
    // 1. It opens with the session key; the seal's signer wrote the rumor.
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
    if status != "approved" && status != "rejected" {
        return Dropped("unknown status");
    }
    // 3. The content: this permission, this challenge.
    if rumor.content.len() > MAX_ANSWER_CONTENT {
        return Dropped("content too large");
    }
    let Ok(content) = serde_json::from_str::<Value>(&rumor.content) else {
        return Dropped("content is not JSON");
    };
    if !content.is_object() {
        return Dropped("content is not a JSON object");
    }
    if json_str(&content, "type") != Some(RESPONSE_TYPE) {
        return Dropped("not an app-permission response");
    }
    if json_str(&content, "permission") != Some(PERMISSION) {
        return Dropped("another permission");
    }
    if json_str(&content, "challenge")
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some(req.challenge.as_str())
    {
        return Dropped("content for another challenge");
    }
    // 4. A denial: `denied: true` and nothing signed. Any signer.
    if status == "rejected" {
        if content.get("denied") != Some(&Value::Bool(true)) {
            return Dropped("rejected without denied");
        }
        if content.get("event").is_some() {
            return Dropped("rejected with an event");
        }
        return Denied;
    }
    // 5. An approval: the template, signed by the persona that sealed it.
    if content.get("denied").is_some() {
        return Dropped("approved with denied");
    }
    let Some(event_json) = content.get("event").filter(|v| v.is_object()) else {
        return Dropped("no event");
    };
    if event_json.to_string().len() > MAX_ATTESTATION_LEN {
        return Dropped("event too large");
    }
    let Ok(event) = serde_json::from_value::<Event>(event_json.clone()) else {
        return Dropped("malformed event");
    };
    if event.as_json().len() > MAX_ATTESTATION_LEN {
        return Dropped("event too large");
    }
    // Recomputes the id from the contents, then checks the Schnorr signature.
    if event.verify().is_err() {
        return Dropped("event signature does not check out");
    }
    let t = &req.template;
    if t["kind"] != event.kind.as_u16()
        || t["pubkey"] != event.pubkey.to_hex().as_str()
        || t["content"] != event.content.as_str()
        || tag_lists(&event) != t["tags"]
    {
        return Dropped("event is not the template");
    }
    if event.pubkey != seal_author {
        return Dropped("event and seal signed by different keys");
    }
    if verify_attestation_event(&req.app_id, &event, &req.runtime, now).is_err() {
        return Dropped("event is not a valid attestation");
    }
    PermissionVerdict::Approved(Box::new(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::unsigned_attestation;
    use nostr::{EventBuilder, Tag};

    const ORIGIN: &str = "https://example.org";
    const APP: &str = "example-app";
    const NAME: &str = "Example App";
    const REASON: &str = "Example App shows the other players in a game that it's really you.";
    const RELAY: &str = "wss://relay.example";

    fn now() -> u64 {
        crate::unix_now()
    }

    struct Fixture {
        persona: Keys,
        runtime: Keys,
        req: PermissionRequest,
    }

    fn fixture() -> Fixture {
        let persona = Keys::generate();
        let runtime = Keys::generate();
        let t = unsigned_attestation(APP, &persona.public_key(), &runtime.public_key(), now());
        let req = PermissionRequest::new(ORIGIN, NAME, REASON, &t, RELAY, now()).unwrap();
        Fixture {
            persona,
            runtime,
            req,
        }
    }

    // ── A port of app-permission.ts's request parser (D1, D2) ──

    fn ts_bounded(raw: &str, max: usize) -> bool {
        // sanitizeDisplayName uncapped, FORMAT_CHARS, trim, count.
        let a: String = raw
            .chars()
            .filter(|c| {
                !matches!(*c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{200b}'..='\u{200f}'
                    | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            })
            .collect();
        let b: String = a.trim().chars().filter(|c| !is_format_char(*c)).collect();
        let n = b.trim().chars().count();
        n >= 1 && n <= max
    }

    fn ts_template(o: &Value, now_s: u64) -> Result<(), &'static str> {
        let Some(map) = o.as_object() else {
            return Err("keys");
        };
        let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
        keys.sort();
        if keys != ["content", "kind", "pubkey", "tags"] {
            return Err("keys");
        }
        if o["kind"] != json!(30420) {
            return Err("kind");
        }
        if o["content"] != json!("") {
            return Err("content");
        }
        let pubkey = o["pubkey"]
            .as_str()
            .filter(|s| is_lower_hex64(s))
            .ok_or("pubkey")?;
        let tags = o["tags"]
            .as_array()
            .filter(|t| t.len() == 7)
            .ok_or("tags")?;
        let mut values = std::collections::HashMap::new();
        for tag in tags {
            let t = tag.as_array().ok_or("tags")?;
            if t.len() != 2 || !t[0].is_string() || !t[1].is_string() {
                return Err("tags");
            }
            let (n, v) = (t[0].as_str().unwrap(), t[1].as_str().unwrap());
            if !TAG_NAMES.contains(&n) || values.insert(n, v).is_some() {
                return Err("tags");
            }
        }
        let d = values["d"];
        if d.is_empty()
            || d.len() > 64
            || !d
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("d");
        }
        if !is_point(values["p"]) || values["p"] == pubkey {
            return Err("p");
        }
        let from = uint(values["valid_from"]).ok_or("valid_from")?;
        if from.abs_diff(now_s) > 300 {
            return Err("valid_from");
        }
        let until = uint(values["valid_until"]).ok_or("valid_until")?;
        if until <= from || until > from + 90 * 86400 {
            return Err("valid_until");
        }
        if values["v"] != "1" {
            return Err("v");
        }
        if values["role"] != "player" {
            return Err("role");
        }
        if values["expiration"] != values["valid_until"] {
            return Err("expiration");
        }
        Ok(())
    }

    /// `parseAppPermissionRequest`, check for check.
    fn ts_parse(link: &str, now_s: u64) -> Result<Value, &'static str> {
        let u = Url::parse(link).map_err(|_| "action")?;
        let q = |k: &str| {
            u.query_pairs()
                .find(|(a, _)| a == k)
                .map(|(_, v)| v.into_owned())
        };
        if q("action").as_deref() != Some("app-permission") {
            return Err("action");
        }
        if q("permission").as_deref() != Some("online-play") {
            return Err("permission");
        }
        let origin = Url::parse(&q("origin").unwrap_or_default()).map_err(|_| "origin")?;
        if origin.scheme() != "https" {
            return Err("origin");
        }
        let callback = Url::parse(&q("callback").unwrap_or_default()).map_err(|_| "callback")?;
        if callback.scheme() != "https" || callback.origin() != origin.origin() {
            return Err("callback");
        }
        let t = uint(&q("t").unwrap_or_default()).ok_or("t")?;
        if now_s.abs_diff(t) > 300 {
            return Err("t");
        }
        let ch = q("challenge").unwrap_or_default();
        if ch.len() != 64 || !ch.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("challenge");
        }
        let relay = q("relay").unwrap_or_default();
        if relay.is_empty()
            || relay.len() > 1024
            || !relay.to_ascii_lowercase().starts_with("wss://")
        {
            return Err("relay");
        }
        if !is_point(&q("sessionPubkey").unwrap_or_default().to_ascii_lowercase()) {
            return Err("session");
        }
        if !ts_bounded(&q("name").unwrap_or_default(), 64) {
            return Err("name");
        }
        if !ts_bounded(&q("reason").unwrap_or_default(), 200) {
            return Err("reason");
        }
        let raw = q("template").unwrap_or_default();
        if raw.is_empty() || raw.len() > 4096 {
            return Err("template");
        }
        let trimmed = raw.trim_end_matches('=');
        if !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("template");
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(trimmed)
            .map_err(|_| "template")?;
        let json: Value = serde_json::from_slice(&bytes).map_err(|_| "template")?;
        ts_template(&json, now_s).map_err(|_| "template")?;
        Ok(json)
    }

    // ── Answers, built with the nostr crate's NIP-59 helpers ──

    fn rumor(author: &PublicKey, tags: Vec<[String; 2]>, content: String) -> UnsignedEvent {
        EventBuilder::new(Kind::Custom(RESPONSE_KIND), content)
            .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
            .build(*author)
    }

    /// Seal by `seal_key` (whose key the rumor must name), wrap by an ephemeral key.
    fn wrap(seal_key: &Keys, to: &PublicKey, r: UnsignedEvent) -> Event {
        crate::runtime()
            .block_on(EventBuilder::gift_wrap(seal_key, to, r, []))
            .unwrap()
    }

    fn signed_template(
        req: &PermissionRequest,
        by: &Keys,
        edit: impl FnOnce(&mut Vec<Vec<String>>),
    ) -> Event {
        let mut tags: Vec<Vec<String>> =
            serde_json::from_value(req.template["tags"].clone()).unwrap();
        edit(&mut tags);
        EventBuilder::new(Kind::Custom(ATTESTATION_KIND), "")
            .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
            .sign_with_keys(by)
            .unwrap()
    }

    fn approved_content(req: &PermissionRequest, event: &Event) -> Value {
        json!({"type": RESPONSE_TYPE, "permission": PERMISSION, "challenge": req.challenge, "event": event})
    }

    fn st(session: &str, status: &str) -> Vec<[String; 2]> {
        vec![
            ["session".into(), session.into()],
            ["status".into(), status.into()],
        ]
    }

    fn approval(f: &Fixture, content: Value) -> Event {
        let r = rumor(
            &f.persona.public_key(),
            st(&f.req.challenge, "approved"),
            content.to_string(),
        );
        wrap(&f.persona, &f.req.session_pubkey(), r)
    }

    fn approve_with(f: &Fixture, edit: impl FnOnce(&mut Vec<Vec<String>>)) -> PermissionVerdict {
        let ev = signed_template(&f.req, &f.persona, edit);
        judge(&f.req, &approval(f, approved_content(&f.req, &ev)), now())
    }

    #[test]
    fn our_request_passes_the_my_signet_parser_rules() {
        let f = fixture();
        let link = f.req.url();
        let template = ts_parse(&link, now()).expect("My Signet would accept it");
        // Exactly the four keys, the attestation's tag order kept.
        assert_eq!(template["pubkey"], json!(f.persona.public_key().to_hex()));
        let names: Vec<&str> = template["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t[0].as_str().unwrap())
            .collect();
        assert_eq!(names, TAG_NAMES);
        assert_eq!(
            template["tags"][1][1],
            json!(f.runtime.public_key().to_hex())
        );
        let u = Url::parse(&link).unwrap();
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(q["name"], NAME);
        assert_eq!(q["reason"], REASON);
        assert_eq!(q["callback"], format!("{ORIGIN}/signet"));
        assert_eq!(q["relay"], RELAY);
        assert_eq!(q["challenge"], f.req.challenge);
        assert!(!format!("{:?}", f.req).contains(&f.req.challenge));
        // Fresh each time.
        let g = fixture();
        assert_ne!(f.req.challenge, g.req.challenge);
        assert_ne!(f.req.session_pubkey(), g.req.session_pubkey());
        // A stale link is one the parser refuses: the clock rules are real.
        assert_eq!(ts_parse(&link, now() + 400), Err("t"));
    }

    #[test]
    fn an_approval_of_the_exact_template_is_accepted() {
        let f = fixture();
        let ev = signed_template(&f.req, &f.persona, |_| {});
        let v = judge(&f.req, &approval(&f, approved_content(&f.req, &ev)), now());
        assert_eq!(v, PermissionVerdict::Approved(Box::new(ev.clone())));
        let info = verify_attestation_event(APP, &ev, &f.runtime.public_key(), now()).unwrap();
        assert_eq!(info.persona, f.persona.public_key());
        assert_eq!(format!("{v:?}"), "Approved");
    }

    #[test]
    fn a_rejection_from_a_throwaway_key_is_a_denial() {
        let f = fixture();
        let throwaway = Keys::generate();
        let content = json!({"type": RESPONSE_TYPE, "permission": PERMISSION, "challenge": f.req.challenge, "denied": true});
        let r = rumor(
            &throwaway.public_key(),
            st(&f.req.challenge, "rejected"),
            content.to_string(),
        );
        assert_eq!(
            judge(&f.req, &wrap(&throwaway, &f.req.session_pubkey(), r), now()),
            PermissionVerdict::Denied
        );
    }

    #[test]
    fn answers_to_another_ask_are_dropped() {
        let f = fixture();
        let ev = signed_template(&f.req, &f.persona, |_| {});
        // A wrong challenge in the content.
        let mut c = approved_content(&f.req, &ev);
        c["challenge"] = json!("11".repeat(32));
        assert!(matches!(
            judge(&f.req, &approval(&f, c), now()),
            PermissionVerdict::Dropped(_)
        ));
        // A wrong session tag.
        let r = rumor(
            &f.persona.public_key(),
            st(&"22".repeat(32), "approved"),
            approved_content(&f.req, &ev).to_string(),
        );
        assert_eq!(
            judge(&f.req, &wrap(&f.persona, &f.req.session_pubkey(), r), now()),
            PermissionVerdict::Dropped("another session")
        );
        // A wrong rumor kind.
        let r = EventBuilder::new(Kind::Custom(14), approved_content(&f.req, &ev).to_string())
            .tags(
                st(&f.req.challenge, "approved")
                    .into_iter()
                    .map(|t| Tag::parse(t).unwrap()),
            )
            .build(f.persona.public_key());
        assert_eq!(
            judge(&f.req, &wrap(&f.persona, &f.req.session_pubkey(), r), now()),
            PermissionVerdict::Dropped("wrong rumor kind")
        );
        // Wrapped to someone else's session key.
        let other = fixture();
        let r = rumor(
            &f.persona.public_key(),
            st(&f.req.challenge, "approved"),
            approved_content(&f.req, &ev).to_string(),
        );
        assert_eq!(
            judge(
                &f.req,
                &wrap(&f.persona, &other.req.session_pubkey(), r),
                now()
            ),
            PermissionVerdict::Dropped("gift wrap did not open")
        );
    }

    #[test]
    fn the_seal_signer_must_be_the_rumor_author() {
        let f = fixture();
        let ev = signed_template(&f.req, &f.persona, |_| {});
        // The rumor claims the persona, the seal is someone else's.
        let r = rumor(
            &f.persona.public_key(),
            st(&f.req.challenge, "approved"),
            approved_content(&f.req, &ev).to_string(),
        );
        let sealer = Keys::generate();
        let seal = crate::runtime()
            .block_on(nostr::nips::nip59::make_seal(
                &sealer,
                &f.req.session_pubkey(),
                r,
            ))
            .unwrap()
            .sign_with_keys(&sealer)
            .unwrap();
        let w = EventBuilder::gift_wrap_from_seal(&f.req.session_pubkey(), &seal, []).unwrap();
        assert_eq!(
            judge(&f.req, &w, now()),
            PermissionVerdict::Dropped("gift wrap did not open")
        );
    }

    #[test]
    fn an_event_signed_by_another_key_is_dropped() {
        let f = fixture();
        let forger = Keys::generate();
        // Signed and sealed by the forger: the template names the persona.
        let ev = signed_template(&f.req, &forger, |_| {});
        let r = rumor(
            &forger.public_key(),
            st(&f.req.challenge, "approved"),
            approved_content(&f.req, &ev).to_string(),
        );
        assert_eq!(
            judge(&f.req, &wrap(&forger, &f.req.session_pubkey(), r), now()),
            PermissionVerdict::Dropped("event is not the template")
        );
        // Sealed by the persona, the event by the forger.
        let ev = signed_template(&f.req, &forger, |_| {});
        assert_eq!(
            judge(&f.req, &approval(&f, approved_content(&f.req, &ev)), now()),
            PermissionVerdict::Dropped("event is not the template")
        );
    }

    #[test]
    fn any_change_to_the_tags_is_dropped() {
        let f = fixture();
        let not_template = PermissionVerdict::Dropped("event is not the template");
        // Changed.
        assert_eq!(approve_with(&f, |t| t[5][1] = "admin".into()), not_template);
        // Added.
        assert_eq!(
            approve_with(&f, |t| t.push(vec!["k".into(), "1".into()])),
            not_template
        );
        // Removed.
        assert_eq!(
            approve_with(&f, |t| {
                t.pop();
            }),
            not_template
        );
        // Reordered.
        assert_eq!(approve_with(&f, |t| t.swap(4, 5)), not_template);
        // A different `p`: another install.
        let other = Keys::generate().public_key().to_hex();
        assert_eq!(approve_with(&f, |t| t[1][1] = other), not_template);
        // A longer validity.
        assert_eq!(
            approve_with(&f, |t| {
                let v = (now() + 100 * 86_400).to_string();
                t[3][1] = v.clone();
                t[6][1] = v;
            }),
            not_template
        );
    }

    #[test]
    fn a_bad_signature_is_dropped() {
        let f = fixture();
        let ev = signed_template(&f.req, &f.persona, |_| {});
        let mut c = approved_content(&f.req, &ev);
        let sig = c["event"]["sig"].as_str().unwrap().to_string();
        let flipped = match sig.strip_prefix('0') {
            Some(rest) => format!("1{rest}"),
            None => format!("0{}", &sig[1..]),
        };
        c["event"]["sig"] = json!(flipped);
        assert_eq!(
            judge(&f.req, &approval(&f, c), now()),
            PermissionVerdict::Dropped("event signature does not check out")
        );
        // Content changed after signing: the id no longer matches.
        let mut c = approved_content(&f.req, &ev);
        c["event"]["content"] = json!("x");
        assert_eq!(
            judge(&f.req, &approval(&f, c), now()),
            PermissionVerdict::Dropped("event signature does not check out")
        );
    }

    #[test]
    fn oversized_content_is_dropped() {
        let f = fixture();
        let ev = signed_template(&f.req, &f.persona, |_| {});
        let mut c = approved_content(&f.req, &ev);
        c["pad"] = json!("x".repeat(MAX_ANSWER_CONTENT));
        assert_eq!(
            judge(&f.req, &approval(&f, c), now()),
            PermissionVerdict::Dropped("content too large")
        );
    }

    #[test]
    fn status_and_content_must_agree() {
        let f = fixture();
        let ev = signed_template(&f.req, &f.persona, |_| {});
        // Approved, but the content says denied.
        let mut c = approved_content(&f.req, &ev);
        c["denied"] = json!(true);
        assert_eq!(
            judge(&f.req, &approval(&f, c), now()),
            PermissionVerdict::Dropped("approved with denied")
        );
        // Rejected, but the content is an approval.
        let r = rumor(
            &f.persona.public_key(),
            st(&f.req.challenge, "rejected"),
            approved_content(&f.req, &ev).to_string(),
        );
        assert_eq!(
            judge(&f.req, &wrap(&f.persona, &f.req.session_pubkey(), r), now()),
            PermissionVerdict::Dropped("rejected without denied")
        );
        // Rejected with denied and an event.
        let mut c = approved_content(&f.req, &ev);
        c["denied"] = json!(true);
        let r = rumor(
            &f.persona.public_key(),
            st(&f.req.challenge, "rejected"),
            c.to_string(),
        );
        assert_eq!(
            judge(&f.req, &wrap(&f.persona, &f.req.session_pubkey(), r), now()),
            PermissionVerdict::Dropped("rejected with an event")
        );
        // Another permission, another type.
        for (k, v) in [("permission", "contacts"), ("type", "signet-auth-response")] {
            let mut c = approved_content(&f.req, &ev);
            c[k] = json!(v);
            assert!(
                matches!(
                    judge(&f.req, &approval(&f, c), now()),
                    PermissionVerdict::Dropped(_)
                ),
                "{k}"
            );
        }
    }

    #[test]
    fn over_cap_name_or_reason_is_refused_not_cut() {
        let persona = Keys::generate().public_key();
        let t = unsigned_attestation(APP, &persona, &Keys::generate().public_key(), now());
        let make = |name: &str, reason: &str| {
            PermissionRequest::new(ORIGIN, name, reason, &t, RELAY, now()).map(|r| r.url())
        };
        assert_eq!(make(&"n".repeat(65), REASON).err(), Some(BAD_NAME));
        assert!(make(&"n".repeat(64), REASON).is_ok());
        assert_eq!(make(NAME, &"r".repeat(201)).err(), Some(BAD_REASON));
        assert!(make(NAME, &"r".repeat(200)).is_ok());
        assert_eq!(make("  \u{200b}\u{ad} ", REASON).err(), Some(BAD_NAME));
        assert_eq!(make(NAME, "").err(), Some(BAD_REASON));
        // Code points, not bytes: 64 emoji fit.
        assert!(make(&"\u{1f600}".repeat(64), REASON).is_ok());
        // Invisible and format characters are stripped as the parser does,
        // before the count.
        let link = make(
            &format!("Ex\u{2060}ample\u{ad}{}", "\u{feff}".repeat(80)),
            REASON,
        )
        .unwrap();
        let u = Url::parse(&link).unwrap();
        assert_eq!(
            u.query_pairs().find(|(k, _)| k == "name").unwrap().1,
            "Example"
        );
        assert!(ts_parse(&link, now()).is_ok());
        assert_eq!(
            bounded_text(" A\u{202e}b\u{180e}c ", 64).as_deref(),
            Some("Abc")
        );
    }

    #[test]
    fn a_template_over_the_param_cap_or_off_the_shape_is_refused() {
        let persona = Keys::generate().public_key();
        let runtime = Keys::generate().public_key();
        let n = now();
        let make =
            |t: &UnsignedEvent| PermissionRequest::new(ORIGIN, NAME, REASON, t, RELAY, n).err();
        // Over 4096 characters once encoded (the size is checked first).
        let base = unsigned_attestation(APP, &persona, &runtime, n);
        let big = {
            let mut tags: Vec<Vec<String>> =
                base.tags.iter().map(|t| t.as_slice().to_vec()).collect();
            tags[0][1] = "a".repeat(3200);
            EventBuilder::new(Kind::Custom(ATTESTATION_KIND), "")
                .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
                .custom_created_at(Timestamp::from(n))
                .build(persona)
        };
        assert!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(template_json(&big).to_string())
                .len()
                > TEMPLATE_PARAM_MAX
        );
        assert_eq!(make(&big), Some(TEMPLATE_TOO_LARGE));
        // Off the one shape.
        let stale = unsigned_attestation(APP, &persona, &runtime, n - 400);
        assert_eq!(make(&stale), Some(BAD_TEMPLATE));
        let self_p = unsigned_attestation(APP, &persona, &persona, n);
        assert_eq!(make(&self_p), Some(BAD_TEMPLATE));
        let bad_id = unsigned_attestation("Example App", &persona, &runtime, n);
        assert_eq!(make(&bad_id), Some(BAD_TEMPLATE));
        assert!(make(&base).is_none());
        // Origin and relay rules.
        assert_eq!(
            PermissionRequest::new("https://example.org/", NAME, REASON, &base, RELAY, n).err(),
            Some(signin::NO_ORIGIN)
        );
        assert_eq!(
            PermissionRequest::new(ORIGIN, NAME, REASON, &base, "ws://r.example", n).err(),
            Some(signin::NO_RELAY)
        );
        let long_relay = format!("wss://r.example/{}", "x".repeat(RELAY_MAX));
        assert_eq!(
            PermissionRequest::new(ORIGIN, NAME, REASON, &base, &long_relay, n).err(),
            Some(signin::NO_RELAY)
        );
    }
}
