//! Frozen constants of the contacts app-access wire v2 (WIRE.md §0, §6, §8).
//! Port of upstream `src/wire/constants.ts`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const PAIRING_SCHEME: &str = "signet-grant:";
pub const PAIRING_VERSION: u64 = 2;
/// Ephemeral pairing ack carrier.
pub const ACK_KIND: u16 = 21237;
/// Stored copy of the pairing ack, `d = ack_tag(challenge)`.
pub const ACK_STORED_KIND: u16 = 30078;
pub const PROJECTION_KIND: u16 = 30078;
pub const PAIRING_FRESHNESS_SECONDS: u64 = 300;
/// Ack candidates a consumer considers per poll (WIRE.md §3, I3).
pub const ACK_CANDIDATE_LIMIT: usize = 10;
/// Total decrypt attempts an ack waiter may spend (upstream `client.ts`).
pub const ACK_ATTEMPT_CAP: usize = 32;
/// Default ack wait: two freshness windows back to back (WIRE.md §3).
pub const ACK_DEFAULT_TIMEOUT_SECONDS: u64 = 2 * PAIRING_FRESHNESS_SECONDS;

pub const DEFAULT_STALENESS_SECONDS: u64 = 21_600;
pub const MIN_STALENESS_SECONDS: u64 = 3_600;
pub const MAX_STALENESS_SECONDS: u64 = 604_800;

#[allow(dead_code)] // wire-constants port of upstream — kept whole so the conformance suite stays a 1:1 mirror
pub const MAX_WIRE_BYTES: usize = 65_532;
pub const MAX_APP_NAME: usize = 64;
pub const MAX_CAPABILITIES: usize = 16;
pub const MAX_CONTACTS_PER_PROJECTION: usize = 2000;
pub const MAX_IDENTITIES_PER_CONTACT: usize = 16;
pub const MAX_METHODS_PER_CONTACT: usize = 16;
pub const MAX_ROLES_PER_CONTACT: usize = 8;
pub const MAX_CHECKS_PER_CONTACT: usize = 128;
pub const MAX_DISPLAY_NAME: usize = 100;
pub const MAX_ROLE_LEN: usize = 40;
pub const MAX_METHOD_VALUE: usize = 320;
pub const MAX_RELAY_LEN: usize = 256;
pub const CHALLENGE_HEX_CHARS: usize = 32;
#[allow(dead_code)] // wire-constants port of upstream — kept whole so the conformance suite stays a 1:1 mirror
pub const MAX_PAIRING_URI_CHARS: usize = 2048;
/// Hard cap on an envelope `content` string before it is parsed (envelope.ts).
pub const MAX_ENVELOPE_CHARS: usize = 100_000;

/// A capability token. Declaration order IS the binding `CAPABILITIES` order
/// (grant-screen order, and the order `scopes` is normalised to).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    ReadDirectory,
    ReadMethodPhone,
    ReadMethodEmail,
    ReadMethodWebsite,
    ReadMethodPostalAddress,
    ReadMethodOther,
    ReadTier,
    ReadChecks,
    ReadCheckRecords,
    ReadRoles,
    BlocksRead,
    ProposeAddKen,
    ProposeRenameAppLabel,
    InvitesCreate,
    InvitesReceive,
}

impl Capability {
    pub const ALL: [Capability; 15] = [
        Capability::ReadDirectory,
        Capability::ReadMethodPhone,
        Capability::ReadMethodEmail,
        Capability::ReadMethodWebsite,
        Capability::ReadMethodPostalAddress,
        Capability::ReadMethodOther,
        Capability::ReadTier,
        Capability::ReadChecks,
        Capability::ReadCheckRecords,
        Capability::ReadRoles,
        Capability::BlocksRead,
        Capability::ProposeAddKen,
        Capability::ProposeRenameAppLabel,
        Capability::InvitesCreate,
        Capability::InvitesReceive,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::ReadDirectory => "signet.contacts.read:directory",
            Capability::ReadMethodPhone => "signet.contacts.read:method:phone",
            Capability::ReadMethodEmail => "signet.contacts.read:method:email",
            Capability::ReadMethodWebsite => "signet.contacts.read:method:website",
            Capability::ReadMethodPostalAddress => "signet.contacts.read:method:postal-address",
            Capability::ReadMethodOther => "signet.contacts.read:method:other",
            Capability::ReadTier => "signet.contacts.read:tier",
            Capability::ReadChecks => "signet.contacts.read:checks",
            Capability::ReadCheckRecords => "signet.contacts.read:check-records",
            Capability::ReadRoles => "signet.contacts.read:roles",
            Capability::BlocksRead => "signet.contacts.blocks.read",
            Capability::ProposeAddKen => "signet.contacts.propose:add-ken",
            Capability::ProposeRenameAppLabel => "signet.contacts.propose:rename-app-label",
            Capability::InvitesCreate => "signet.contacts.invites:create",
            Capability::InvitesReceive => "signet.contacts.invites:receive",
        }
    }

    /// Exact-match lookup; anything else is not a capability.
    pub fn parse(token: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| c.as_str() == token)
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Capability::parse(&s).ok_or_else(|| serde::de::Error::custom("unknown capability"))
    }
}

/// Dedupe and sort into `CAPABILITIES` order (`normaliseCapabilities`).
pub fn normalise_capabilities(input: &[Capability]) -> Vec<Capability> {
    Capability::ALL.into_iter().filter(|c| input.contains(c)).collect()
}

/// `clampStaleness`: non-positive / non-finite / absent → default; otherwise
/// floored and clamped into `[MIN, MAX]`.
pub fn clamp_staleness(seconds: Option<f64>) -> u64 {
    match seconds {
        Some(s) if s.is_finite() && s > 0.0 => {
            let whole = s.floor();
            if whole < MIN_STALENESS_SECONDS as f64 {
                MIN_STALENESS_SECONDS
            } else if whole > MAX_STALENESS_SECONDS as f64 {
                MAX_STALENESS_SECONDS
            } else {
                whole as u64
            }
        }
        _ => DEFAULT_STALENESS_SECONDS,
    }
}
