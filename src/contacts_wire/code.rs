//! Pairing verification code (WIRE.md §3 B1/F1) — consumer side. Port of
//! upstream `src/wire/pairing-code.ts`. The app shows this code; the person
//! types it into Signet; the app must not use the pairing until they confirm.
//! The code flows one way only — never compare against a code Signet shows.

use sha2::{Digest, Sha256};

use super::guards::is_hex;
use super::pairing::is_valid_challenge;

const PAIRING_CODE_MODULUS: u32 = 1_000_000;

/// Deterministic 6-digit code, e.g. `"042917"`, from values only a real ack
/// carries (`grant_id`, `rail_pubkey`) plus the app's own. `None` on invalid
/// input (upstream throws): `app_pubkey`/`rail_pubkey` lowercase 64-hex,
/// `grant_id` lowercase 32-hex, `challenge` 32 hex of either case.
pub fn pairing_code(app_pubkey: &str, challenge: &str, grant_id: &str, rail_pubkey: &str) -> Option<String> {
    if !is_hex(app_pubkey, 64)
        || !is_hex(grant_id, 32)
        || !is_hex(rail_pubkey, 64)
        || !is_valid_challenge(challenge)
    {
        return None;
    }
    let payload = format!(
        "signet-contacts:pairing-code:v1\n{}\n{}\n{}\n{}",
        app_pubkey.to_ascii_lowercase(),
        challenge.to_ascii_lowercase(),
        grant_id.to_ascii_lowercase(),
        rail_pubkey.to_ascii_lowercase(),
    );
    let digest = Sha256::digest(payload.as_bytes());
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    Some(format!("{:06}", n % PAIRING_CODE_MODULUS))
}

/// Display grouping only, e.g. `"042 917"`.
pub fn format_pairing_code(code: &str) -> String {
    let split = code.char_indices().nth(3).map_or(code.len(), |(i, _)| i);
    format!("{} {}", &code[..split], &code[split..])
}
