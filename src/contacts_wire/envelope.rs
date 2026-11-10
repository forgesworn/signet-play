//! Vault envelope v2 (WIRE.md §1) — open only. Port of upstream
//! `openVaultPayload` / `parseVaultEnvelope` / `unpad` (`src/wire/envelope.ts`).
//!
//! `content` is `{"v":2,"k":<NIP-44 of base64(contentKey)>,"iv":<b64>,"ct":<b64>,"b":<bucket>}`.
//! Unwrap `k` (NIP-44, app secret ↔ rail pubkey), AES-256-GCM-decrypt `ct`,
//! check the plaintext is exactly `b` bytes, strip the 4-byte big-endian
//! length prefix. Every failure is `None`; there is no bare-NIP-44 fallback.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use nostr::{PublicKey, SecretKey};
use serde_json::Value;

use super::constants::MAX_ENVELOPE_CHARS;
use super::guards::js_uint;

pub const BUCKETS: [usize; 5] = [4096, 8192, 16384, 32768, 65536];
pub const LENGTH_PREFIX_BYTES: usize = 4;
const IV_LENGTH: usize = 12;
const CONTENT_KEY_BYTES: usize = 32;

/// `atob`-compatible: standard alphabet, padding optional.
const B64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The parsed shape of a sealed `content`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEnvelope {
    pub k: String,
    pub iv: String,
    pub ct: String,
    pub b: usize,
}

/// Shape-check a `content` string. Size cap BEFORE the JSON parse.
pub fn parse_vault_envelope(content: &str) -> Option<VaultEnvelope> {
    if content.len() > MAX_ENVELOPE_CHARS {
        return None;
    }
    let raw: Value = serde_json::from_str(content).ok()?;
    let e = raw.as_object()?;
    if js_uint(e.get("v")) != Some(2) {
        return None;
    }
    let k = e.get("k")?.as_str()?;
    let iv = e.get("iv")?.as_str()?;
    let ct = e.get("ct")?.as_str()?;
    let b = js_uint(e.get("b")).and_then(|b| usize::try_from(b).ok())?;
    if !BUCKETS.contains(&b) {
        return None;
    }
    Some(VaultEnvelope { k: k.to_owned(), iv: iv.to_owned(), ct: ct.to_owned(), b })
}

/// Reverse the 4-byte big-endian length prefix + zero padding.
pub fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let prefix: [u8; LENGTH_PREFIX_BYTES] = padded.get(..LENGTH_PREFIX_BYTES)?.try_into().ok()?;
    let len = u32::from_be_bytes(prefix) as usize;
    padded.get(LENGTH_PREFIX_BYTES..LENGTH_PREFIX_BYTES.checked_add(len)?)
}

/// Open a v2 envelope sealed by `rail_pubkey` to the app. Returns the body
/// bytes, or `None` on ANY failure (malformed envelope, wrong key, tampered
/// ciphertext, relabelled bucket, bad padding).
pub fn open_vault_envelope(content: &str, app_secret: &SecretKey, rail_pubkey: &PublicKey) -> Option<Vec<u8>> {
    let env = parse_vault_envelope(content)?;
    let wrapped = nostr::nips::nip44::decrypt(app_secret, rail_pubkey, &env.k).ok()?;
    let mut raw_key = B64.decode(wrapped.as_bytes()).ok()?;
    if raw_key.len() != CONTENT_KEY_BYTES {
        raw_key.fill(0);
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(&raw_key).ok();
    raw_key.fill(0);
    let cipher = cipher?;
    let iv = B64.decode(env.iv.as_bytes()).ok()?;
    if iv.len() != IV_LENGTH {
        return None;
    }
    let ct = B64.decode(env.ct.as_bytes()).ok()?;
    let nonce = Nonce::try_from(iv.as_slice()).ok()?;
    let mut padded = cipher.decrypt(&nonce, ct.as_slice()).ok()?;
    // The declared bucket must match what came out — a mismatch means the
    // envelope was relabelled.
    let body = if padded.len() == env.b { unpad(&padded).map(<[u8]>::to_vec) } else { None };
    padded.fill(0);
    body
}

/// [`open_vault_envelope`] decoded as UTF-8 (`None` on invalid UTF-8, where
/// upstream's `TextDecoder` would substitute U+FFFD).
pub fn open_vault_envelope_text(content: &str, app_secret: &SecretKey, rail_pubkey: &PublicKey) -> Option<String> {
    String::from_utf8(open_vault_envelope(content, app_secret, rail_pubkey)?).ok()
}
