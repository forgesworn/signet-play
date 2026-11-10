//! §4 tag derivations: domain-separated SHA-256, truncated to 128 bits
//! (32 lowercase hex). Port of upstream `src/wire/ids.ts`.

use sha2::{Digest, Sha256};

const PROJECTION_PREFIX: &str = "signet:contacts:proj:";
#[allow(dead_code)] // port of upstream ids.ts — kept whole; the proposal/scoped-id derivations are conformance-tested
const PROPOSAL_PREFIX: &str = "signet:contacts:prop:";
#[allow(dead_code)] // port of upstream ids.ts — kept whole; the proposal/scoped-id derivations are conformance-tested
const SCOPED_PREFIX: &str = "signet:contacts:cid:";
const ACK_PREFIX: &str = "signet:contacts:ack:";
const TAG_HEX_CHARS: usize = 32;

fn digest_tag(input: &str) -> String {
    let mut hex = hex::encode(Sha256::digest(input.as_bytes()));
    hex.truncate(TAG_HEX_CHARS);
    hex
}

/// JavaScript `.length` (UTF-16 code units) — what upstream mixes into
/// `scopedContactId`. Identical to the byte length for the hex ids on this wire.
#[allow(dead_code)] // port of upstream ids.ts — kept whole; the proposal/scoped-id derivations are conformance-tested
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `d` tag of a grant's projection event.
pub fn projection_tag(grant_id: &str) -> String {
    digest_tag(&format!("{PROJECTION_PREFIX}{grant_id}"))
}

/// `d` tag of one app's proposal event for a grant.
#[allow(dead_code)] // port of upstream ids.ts — kept whole; the proposal/scoped-id derivations are conformance-tested
pub fn proposal_tag(grant_id: &str, app_pubkey: &str) -> String {
    digest_tag(&format!("{PROPOSAL_PREFIX}{grant_id}:{app_pubkey}"))
}

/// `d` tag of the stored (kind 30078) pairing ack. The challenge is
/// lowercased before hashing.
pub fn ack_tag(challenge: &str) -> String {
    digest_tag(&format!("{ACK_PREFIX}{}", challenge.to_lowercase()))
}

/// Grant-scoped opaque contact id; input lengths are mixed in first so
/// `("ab","c:d")` and `("ab:c","d")` cannot collide.
#[allow(dead_code)] // port of upstream ids.ts — kept whole; the proposal/scoped-id derivations are conformance-tested
pub fn scoped_contact_id(grant_id: &str, contact_id: &str) -> String {
    digest_tag(&format!(
        "{SCOPED_PREFIX}{}:{grant_id}:{}:{contact_id}",
        js_len(grant_id),
        js_len(contact_id)
    ))
}
