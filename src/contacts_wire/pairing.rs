//! Pairing URI v2 (WIRE.md §3) — the `signet-grant:` string an app shows as a
//! QR code, and the web carrier for a desktop-to-phone hand-off. Port of the
//! builder half of upstream `src/wire/pairing.ts`. Parameter order is binding;
//! `vectors/pairing.v2.json` pins the bytes.

use super::constants::{
    normalise_capabilities, Capability, CHALLENGE_HEX_CHARS, MAX_APP_NAME, MAX_RELAY_LEN,
    PAIRING_SCHEME, PAIRING_VERSION,
};
use super::guards::is_hex;
use super::sanitise::sanitize_wire_text;

/// Whose directory a pairing reads (`dir=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directory {
    Owner,
    #[allow(dead_code)] // the dependant directory — the kids/dependant gap is not built yet (tests construct it)
    Dependant,
}

impl Directory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Directory::Owner => "owner",
            Directory::Dependant => "dependant",
        }
    }
}

/// Why a pairing URI could not be built. Builders refuse rather than repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    /// Not lowercase 64-hex.
    AppPubkey,
    /// Empty, or changed by the wire sanitiser (control/bidi characters,
    /// surrounding whitespace, or longer than 64 code points).
    AppName,
    /// No capability requested.
    NoCapabilities,
    /// Not `wss://` (or loopback `ws://`), or over 256 characters.
    Relay,
    /// Not exactly 32 hex characters.
    Challenge,
}

/// `isValidContactsRelayUrl`: 1..=256 characters, `wss://` (case-insensitive)
/// or loopback `ws://localhost` / `ws://127.0.0.1` followed by `:`, `/` or end.
pub fn is_valid_contacts_relay_url(value: &str) -> bool {
    // Counted as JS `.length` (UTF-16 units), as upstream does.
    let len = value.encode_utf16().count();
    if len == 0 || len > MAX_RELAY_LEN {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("wss://") {
        return true;
    }
    for host in ["ws://localhost", "ws://127.0.0.1"] {
        if let Some(rest) = lower.strip_prefix(host)
            && (rest.is_empty() || rest.starts_with(':') || rest.starts_with('/'))
        {
            return true;
        }
    }
    false
}

/// Exactly 32 hex characters, either case (validated case-insensitively,
/// echoed verbatim).
pub fn is_valid_challenge(value: &str) -> bool {
    value.len() == CHALLENGE_HEX_CHARS && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// WHATWG `application/x-www-form-urlencoded` byte serialiser — exactly what
/// `URLSearchParams.toString()` emits: `A-Za-z0-9*-._` kept, space → `+`,
/// everything else `%XX` (uppercase).
fn form_urlencode(value: &str, out: &mut String) {
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
}

/// Build the `signet-grant://pair?…` URI. `caps` is normalised (deduped,
/// `CAPABILITIES` order) regardless of the order given.
pub fn build_pairing_uri(
    app_pubkey: &str,
    name: &str,
    caps: &[Capability],
    dir: Directory,
    relay: &str,
    t: u64,
    challenge: &str,
) -> Result<String, PairingError> {
    if !is_hex(app_pubkey, 64) {
        return Err(PairingError::AppPubkey);
    }
    if !is_valid_contacts_relay_url(relay) {
        return Err(PairingError::Relay);
    }
    if !is_valid_challenge(challenge) {
        return Err(PairingError::Challenge);
    }
    let caps = normalise_capabilities(caps);
    if caps.is_empty() {
        return Err(PairingError::NoCapabilities);
    }
    // Stricter than upstream's builder (which leaves this to the parser): a
    // name Signet would rewrite is a name the owner would not see as sent.
    if name.is_empty() || sanitize_wire_text(name, MAX_APP_NAME) != name {
        return Err(PairingError::AppName);
    }
    let caps_joined = caps.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(",");
    let params: [(&str, &str); 8] = [
        ("v", &PAIRING_VERSION.to_string()),
        ("app", app_pubkey),
        ("name", name),
        ("caps", &caps_joined),
        ("dir", dir.as_str()),
        ("relay", relay),
        ("t", &t.to_string()),
        ("challenge", challenge),
    ];
    let mut uri = format!("{PAIRING_SCHEME}//pair?");
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            uri.push('&');
        }
        form_urlencode(k, &mut uri);
        uri.push('=');
        form_urlencode(v, &mut uri);
    }
    Ok(uri)
}

/// The web carrier (WIRE.md §3 "Carriers"): the same query string behind
/// `https://<host>/?pair=1&…`. `host` is the deployment Signet publishes
/// (the caller's constant — this wire does not hard-code one). Everything
/// after the first `?` of `uri` is carried unchanged.
pub fn web_carrier(host: &str, uri: &str) -> String {
    let query = uri.split_once('?').map_or(uri, |(_, q)| q);
    format!("https://{host}/?pair=1&{query}")
}
