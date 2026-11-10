//! Kind 30420 runtime-key attestation: the persona (via My Signet) signs one
//! event saying "this install's runtime key plays the game as me".
//!
//! Adapted from the attestation and runtime-identity code of an earlier game
//! codebase (`mint_player_attestation`, `verify_player_attestation`; see
//! `NOTICE`). Differences: the `d` tag is the game's app id (passed in by
//! the caller; the crate names no game), so the runtime key is bound by the
//! `p` tag; a NIP-40 `expiration` tag equal to `valid_until`; no `k` tags.
//!
//! **It is never published** (kit rules 1-2). It stays on the phone and
//! is sent only inside an encrypted channel, to people in a game or lobby with
//! you, or inside a gift-wrapped invite.
//!
//! Tags: `d`=app id, `p`=runtime pubkey hex, `valid_from`, `valid_until`
//! (unix secs), `v`=`1`, `role`=`player`, `expiration`. Content is empty.

use nostr::{Event, EventBuilder, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};

pub const ATTESTATION_KIND: u16 = 30420;
pub const ATTESTATION_VERSION: &str = "1";
pub const PLAYER_ROLE: &str = "player";
/// Lifetime of a freshly minted attestation.
pub const VALIDITY_SECS: u64 = 90 * 86_400;
/// Re-mint when less than this is left.
pub const REFRESH_SECS: u64 = 7 * 86_400;
/// Longest attestation accepted (matches the hello slot of the game connection).
pub const MAX_ATTESTATION_LEN: usize = 2048;
/// Tolerated clock skew on `valid_from`.
pub const CLOCK_SKEW_SECS: u64 = 300;
/// What a verified attestation says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonaInfo {
    /// The persona that signed it (the identity peers should show and match).
    pub persona: PublicKey,
    /// The runtime key it vouches for.
    pub runtime: PublicKey,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationError {
    TooLarge,
    Malformed(&'static str),
    BadSignature,
    BadKind,
    BadVersion,
    /// `d` is not this game's app id.
    WrongApp,
    /// `role` is not `player`.
    WrongRole,
    /// `p` names a different runtime key than the one presenting it.
    WrongRuntimeKey,
    NotYetValid,
    Expired,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationError::TooLarge => f.write_str("attestation too large"),
            AttestationError::Malformed(m) => write!(f, "malformed attestation: {m}"),
            AttestationError::BadSignature => f.write_str("attestation signature does not verify"),
            AttestationError::BadKind => f.write_str("not a kind 30420 attestation"),
            AttestationError::BadVersion => f.write_str("unknown attestation version"),
            AttestationError::WrongApp => f.write_str("attestation is for another app"),
            AttestationError::WrongRole => f.write_str("attestation is not a player attestation"),
            AttestationError::WrongRuntimeKey => {
                f.write_str("attestation names a different runtime key")
            }
            AttestationError::NotYetValid => f.write_str("attestation is not valid yet"),
            AttestationError::Expired => f.write_str("attestation has expired"),
        }
    }
}

impl std::error::Error for AttestationError {}

fn first_tag<'a>(ev: &'a Event, name: &str) -> Option<&'a str> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.len() >= 2 && s[0] == name).then(|| s[1].as_str())
    })
}

fn tag(parts: [&str; 2]) -> Tag {
    Tag::parse(parts).expect("two-element tag always parses")
}

/// The unsigned attestation for `persona` to sign over `runtime` for the game
/// `app_id`, valid from `now` for [`VALIDITY_SECS`].
pub fn unsigned_attestation(
    app_id: &str,
    persona: &PublicKey,
    runtime: &PublicKey,
    now: u64,
) -> UnsignedEvent {
    let until = now.saturating_add(VALIDITY_SECS);
    let rt = runtime.to_hex();
    EventBuilder::new(Kind::Custom(ATTESTATION_KIND), "")
        .tags([
            tag(["d", app_id]),
            tag(["p", &rt]),
            tag(["valid_from", &now.to_string()]),
            tag(["valid_until", &until.to_string()]),
            tag(["v", ATTESTATION_VERSION]),
            tag(["role", PLAYER_ROLE]),
            tag(["expiration", &until.to_string()]),
        ])
        .custom_created_at(Timestamp::from(now))
        .build(*persona)
}

/// The runtime key an attestation names (its `p` tag), without verifying it.
pub fn named_runtime(ev: &Event) -> Option<PublicKey> {
    first_tag(ev, "p").and_then(|p| PublicKey::from_hex(p).ok())
}

/// When the attestation event was made (`created_at`), from its JSON, without
/// verifying it. Callers verify first; this orders two attestations of the
/// same persona (a newer one wins).
pub(crate) fn created_at_of(json: impl AsRef<[u8]>) -> Option<u64> {
    let ev: Event = serde_json::from_slice(json.as_ref()).ok()?;
    Some(ev.created_at.as_secs())
}

/// The `valid_until` an attestation event claims, without verifying it.
pub fn valid_until_of(ev: &Event) -> Option<u64> {
    first_tag(ev, "valid_until").and_then(|s| s.parse().ok())
}

/// Verify an attestation event: signature, kind, version, `d`=`app_id`,
/// `role`=`player`, `p` = `runtime`, and `now` inside the validity window.
pub fn verify_attestation_event(
    app_id: &str,
    ev: &Event,
    runtime: &PublicKey,
    now: u64,
) -> Result<PersonaInfo, AttestationError> {
    if ev.kind != Kind::Custom(ATTESTATION_KIND) {
        return Err(AttestationError::BadKind);
    }
    if ev.verify().is_err() {
        return Err(AttestationError::BadSignature);
    }
    if first_tag(ev, "v") != Some(ATTESTATION_VERSION) {
        return Err(AttestationError::BadVersion);
    }
    if first_tag(ev, "d") != Some(app_id) {
        return Err(AttestationError::WrongApp);
    }
    if first_tag(ev, "role") != Some(PLAYER_ROLE) {
        return Err(AttestationError::WrongRole);
    }
    let named = named_runtime(ev).ok_or(AttestationError::Malformed("p"))?;
    let valid_from = first_tag(ev, "valid_from")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(AttestationError::Malformed("valid_from"))?;
    let valid_until = first_tag(ev, "valid_until")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(AttestationError::Malformed("valid_until"))?;
    if named != *runtime {
        return Err(AttestationError::WrongRuntimeKey);
    }
    if now.saturating_add(CLOCK_SKEW_SECS) < valid_from {
        return Err(AttestationError::NotYetValid);
    }
    if now > valid_until {
        return Err(AttestationError::Expired);
    }
    Ok(PersonaInfo {
        persona: ev.pubkey,
        runtime: named,
        valid_from,
        valid_until,
    })
}

/// Verify an attestation as carried opaque (event JSON, e.g. from a QUIC
/// hello / welcome) for the runtime key that presented it. Anything over
/// [`MAX_ATTESTATION_LEN`] bytes is refused before parsing.
pub fn verify_attestation(
    app_id: &str,
    event_json: impl AsRef<[u8]>,
    runtime: &PublicKey,
    now: u64,
) -> Result<PersonaInfo, AttestationError> {
    let bytes = event_json.as_ref();
    if bytes.len() > MAX_ATTESTATION_LEN {
        return Err(AttestationError::TooLarge);
    }
    let ev: Event =
        serde_json::from_slice(bytes).map_err(|_| AttestationError::Malformed("not an event"))?;
    verify_attestation_event(app_id, &ev, runtime, now)
}

/// Whether an attestation valid until `valid_until` should be re-minted.
pub fn needs_refresh(valid_until: u64, now: u64) -> bool {
    valid_until.saturating_sub(now) < REFRESH_SECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    const NOW: u64 = 1_800_000_000;
    const APP: &str = "testgame";

    fn minted(persona: &Keys, runtime: &PublicKey, now: u64) -> Event {
        unsigned_attestation(APP, &persona.public_key(), runtime, now)
            .sign_with_keys(persona)
            .unwrap()
    }

    #[test]
    fn mint_round_trips_through_verify() {
        let persona = Keys::generate();
        let runtime = Keys::generate().public_key();
        let ev = minted(&persona, &runtime, NOW);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(
            json.len() <= MAX_ATTESTATION_LEN,
            "fits the hello slot: {}",
            json.len()
        );
        let info = verify_attestation(APP, &json, &runtime, NOW + 10).unwrap();
        assert_eq!(info.persona, persona.public_key());
        assert_eq!(info.runtime, runtime);
        assert_eq!(info.valid_until - info.valid_from, VALIDITY_SECS);
        assert_eq!(ev.tags.identifier(), Some(APP));
        assert_eq!(
            first_tag(&ev, "expiration"),
            Some((NOW + VALIDITY_SECS).to_string().as_str())
        );
    }

    #[test]
    fn expiry_window_and_skew() {
        let persona = Keys::generate();
        let runtime = Keys::generate().public_key();
        let ev = minted(&persona, &runtime, NOW);
        assert!(verify_attestation_event(APP, &ev, &runtime, NOW + VALIDITY_SECS).is_ok());
        assert_eq!(
            verify_attestation_event(APP, &ev, &runtime, NOW + VALIDITY_SECS + 1),
            Err(AttestationError::Expired)
        );
        assert!(verify_attestation_event(APP, &ev, &runtime, NOW - CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            verify_attestation_event(APP, &ev, &runtime, NOW - CLOCK_SKEW_SECS - 1),
            Err(AttestationError::NotYetValid)
        );
    }

    #[test]
    fn wrong_binding_is_refused() {
        let persona = Keys::generate();
        let runtime = Keys::generate().public_key();
        let other = Keys::generate().public_key();
        let ev = minted(&persona, &runtime, NOW);
        assert_eq!(
            verify_attestation_event(APP, &ev, &other, NOW),
            Err(AttestationError::WrongRuntimeKey)
        );
    }

    fn with_tags(persona: &Keys, tags: Vec<[&str; 2]>) -> Event {
        EventBuilder::new(Kind::Custom(ATTESTATION_KIND), "")
            .tags(tags.into_iter().map(tag))
            .custom_created_at(Timestamp::from(NOW))
            .sign_with_keys(persona)
            .unwrap()
    }

    #[test]
    fn role_app_version_and_kind_are_checked() {
        let p = Keys::generate();
        let rt = Keys::generate().public_key();
        let rth = rt.to_hex();
        let (from, until) = (NOW.to_string(), (NOW + 100).to_string());
        let base = |d: &'static str, role: &'static str, v: &'static str| {
            vec![
                ["d", d],
                ["p", rth.as_str()],
                ["valid_from", from.as_str()],
                ["valid_until", until.as_str()],
                ["v", v],
                ["role", role],
            ]
        };
        assert!(
            verify_attestation_event(APP, &with_tags(&p, base(APP, "player", "1")), &rt, NOW)
                .is_ok()
        );
        assert_eq!(
            verify_attestation_event(
                APP,
                &with_tags(&p, base("someotherapp", "player", "1")),
                &rt,
                NOW
            ),
            Err(AttestationError::WrongApp)
        );
        assert_eq!(
            verify_attestation_event(APP, &with_tags(&p, base(APP, "server", "1")), &rt, NOW),
            Err(AttestationError::WrongRole)
        );
        assert_eq!(
            verify_attestation_event(APP, &with_tags(&p, base(APP, "player", "2")), &rt, NOW),
            Err(AttestationError::BadVersion)
        );
        let note = EventBuilder::text_note("hi").sign_with_keys(&p).unwrap();
        assert_eq!(
            verify_attestation_event(APP, &note, &rt, NOW),
            Err(AttestationError::BadKind)
        );
    }

    #[test]
    fn tampered_signature_is_refused() {
        let persona = Keys::generate();
        let runtime = Keys::generate().public_key();
        let ev = minted(&persona, &runtime, NOW);
        let mut v = serde_json::to_value(&ev).unwrap();
        v["tags"][3][1] = serde_json::json!((NOW + VALIDITY_SECS * 10).to_string());
        assert_eq!(
            verify_attestation(APP, v.to_string(), &runtime, NOW),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn oversized_and_garbage_input_is_refused() {
        let rt = Keys::generate().public_key();
        assert_eq!(
            verify_attestation(APP, vec![b' '; MAX_ATTESTATION_LEN + 1], &rt, NOW),
            Err(AttestationError::TooLarge)
        );
        assert!(matches!(
            verify_attestation(APP, b"{}", &rt, NOW),
            Err(AttestationError::Malformed(_))
        ));
        assert!(matches!(
            verify_attestation(APP, b"\xff\xfe", &rt, NOW),
            Err(AttestationError::Malformed(_))
        ));
    }

    #[test]
    fn refresh_threshold_is_seven_days() {
        let until = NOW + VALIDITY_SECS;
        assert!(!needs_refresh(until, NOW));
        assert!(!needs_refresh(until, until - REFRESH_SECS));
        assert!(needs_refresh(until, until - REFRESH_SECS + 1));
        assert!(needs_refresh(until, until + 5));
    }
}
