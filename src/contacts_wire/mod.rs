//! Signet contacts app-access wire v2 — the pure CONSUMER half, ported from
//! `forgesworn/signet-contacts` (`docs/WIRE.md`, v2 frozen; upstream fbb13cd).
//! Copied unchanged from the port in an earlier game codebase (see `NOTICE`).
//!
//! No relay I/O, no storage, no game types: this module is liftable to a
//! standalone crate unchanged. Where this port and WIRE.md disagree, WIRE.md
//! wins and this is the bug. Conformance: `tests.rs` against the frozen
//! vectors copied into `vectors/`.
//!
//! Consumer flow (`crate::contacts` wires it): `build_pairing_uri` → QR/`web_carrier` →
//! for each candidate event `ack_event_is_fresh` + `decrypt_ack_event` →
//! show `format_pairing_code(pairing_code(..))` and wait for the person's
//! Continue → fetch kind 30078 `#d=[projection_tag(grant_id)]` authored by the
//! rail → `open_vault_envelope_text` → `parse_projection` (+ check `grant_id`)
//! → keep it only if `is_newer` than what is held.


pub mod ack;
pub mod code;
pub mod constants;
mod coverage;
pub mod envelope;
mod guards;
pub mod pairing;
pub mod projection;
pub mod sanitise;
pub mod tags;

#[cfg(test)]
mod tests;

pub use ack::{ack_event_is_fresh, decrypt_ack_event, parse_ack, Ack};
pub use code::{format_pairing_code, pairing_code};
pub use constants::{clamp_staleness, normalise_capabilities, Capability};
pub use envelope::{open_vault_envelope, open_vault_envelope_text};
pub use pairing::{build_pairing_uri, web_carrier, Directory, PairingError};
pub use projection::{
    frontier_newer, is_newer, parse_projection, Frontier, Identity, ProjectedContact, Projection,
    Tier,
};
pub use sanitise::sanitize_wire_text;
pub use tags::{ack_tag, projection_tag, proposal_tag, scoped_contact_id};
