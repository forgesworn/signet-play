//! Pairing ack v2 (WIRE.md §3, §5) — consumer side. Port of upstream
//! `parsePairingAckV2` plus the per-candidate gates `awaitPairingAck` applies
//! in `src/client.ts` (requested-capability ceiling, self-rail refusal,
//! envelope-size bound, carrier freshness).

use nostr::{Event, Keys, Kind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::constants::{
    clamp_staleness, normalise_capabilities, Capability, ACK_KIND, ACK_STORED_KIND,
    MAX_ENVELOPE_CHARS, PAIRING_FRESHNESS_SECONDS,
};
use super::guards::{js_uint, json_hex};
use super::pairing::is_valid_contacts_relay_url;

/// A validated pairing ack. Shape matches the wire JSON (`v` included) so it
/// can be compared against the vector and persisted as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ack {
    pub v: u8,
    pub grant_id: String,
    pub rail_pubkey: String,
    pub projection_tag: String,
    pub proposal_tag: String,
    pub relay: String,
    pub granted_capabilities: Vec<Capability>,
    pub max_staleness_seconds: u64,
    pub challenge: String,
}

/// Parse an ack plaintext. `None` unless: `v == 2`; `challenge` equals
/// `expected_challenge` byte for byte (case preserved); ids are lowercase hex
/// of the right width; `relay` is a valid contacts relay; at least one known
/// capability is granted; and every granted capability was in `requested`
/// (narrowing only — a wider ack is refused). Unknown capability tokens are
/// dropped; `maxStalenessSeconds` is clamped.
pub fn parse_ack(plaintext: &str, expected_challenge: &str, requested: &[Capability]) -> Option<Ack> {
    let raw: Value = serde_json::from_str(plaintext).ok()?;
    let o = raw.as_object()?;
    if js_uint(o.get("v")) != Some(2) {
        return None;
    }
    let challenge = o.get("challenge")?.as_str()?;
    if challenge != expected_challenge {
        return None;
    }
    let grant_id = json_hex(o.get("grantId"), 32)?;
    let rail_pubkey = json_hex(o.get("railPubkey"), 64)?;
    let projection_tag = json_hex(o.get("projectionTag"), 32)?;
    let proposal_tag = json_hex(o.get("proposalTag"), 32)?;
    let relay = o.get("relay")?.as_str()?;
    if !is_valid_contacts_relay_url(relay) {
        return None;
    }
    let known: Vec<Capability> = o
        .get("grantedCapabilities")?
        .as_array()?
        .iter()
        .filter_map(|c| c.as_str().and_then(Capability::parse))
        .collect();
    let granted = normalise_capabilities(&known);
    if granted.is_empty() || granted.iter().any(|c| !requested.contains(c)) {
        return None;
    }
    Some(Ack {
        v: 2,
        grant_id: grant_id.to_owned(),
        rail_pubkey: rail_pubkey.to_owned(),
        projection_tag: projection_tag.to_owned(),
        proposal_tag: proposal_tag.to_owned(),
        relay: relay.to_owned(),
        granted_capabilities: granted,
        max_staleness_seconds: clamp_staleness(o.get("maxStalenessSeconds").and_then(Value::as_f64)),
        challenge: challenge.to_owned(),
    })
}

/// Open one ack candidate event (kind 21237 or its stored 30078 copy):
/// NIP-44-decrypt `content` from the event's (ephemeral) author to the app
/// key, then `parse_ack`. Also refuses an oversized `content` before any
/// decrypt, and an ack naming the app's own key as its rail. Freshness of the
/// carrier is the caller's check: see [`ack_event_is_fresh`].
pub fn decrypt_ack_event(
    event: &Event,
    app_keys: &Keys,
    expected_challenge: &str,
    requested: &[Capability],
) -> Option<Ack> {
    if event.kind != Kind::Custom(ACK_KIND) && event.kind != Kind::Custom(ACK_STORED_KIND) {
        return None;
    }
    if event.content.len() > MAX_ENVELOPE_CHARS {
        return None;
    }
    let plaintext =
        nostr::nips::nip44::decrypt(app_keys.secret_key(), &event.pubkey, &event.content).ok()?;
    let ack = parse_ack(&plaintext, expected_challenge, requested)?;
    if ack.rail_pubkey == app_keys.public_key().to_hex() {
        return None;
    }
    Some(ack)
}

/// The ack carries no timestamp of its own, so freshness is judged on the
/// carrier event's `created_at`: within `PAIRING_FRESHNESS_SECONDS` of now,
/// either side.
pub fn ack_event_is_fresh(created_at: u64, now: u64) -> bool {
    created_at.abs_diff(now) <= PAIRING_FRESHNESS_SECONDS
}
