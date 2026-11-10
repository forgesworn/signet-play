//! Projection body v2 (WIRE.md §5, §6, §8, §10) — consumer parse. Port of
//! upstream `parseProjection` / `parseProjectedContact` (`projection.ts`) plus
//! the two grant gates `client.ts` applies after it (scopes ⊆ granted,
//! `expiresAt − issuedAt ≤ maxStalenessSeconds`), and the newest-wins order
//! of `state.ts`.
//!
//! Three failure levels: a malformed body, an uncovered field anywhere, or a
//! grant-gate breach → `None` for the whole projection; one malformed contact
//! → that contact dropped; one malformed optional field → that field dropped.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::constants::{
    normalise_capabilities, Capability, MAX_CAPABILITIES, MAX_CHECKS_PER_CONTACT,
    MAX_CONTACTS_PER_PROJECTION, MAX_DISPLAY_NAME, MAX_IDENTITIES_PER_CONTACT,
    MAX_METHODS_PER_CONTACT, MAX_METHOD_VALUE, MAX_ROLES_PER_CONTACT, MAX_ROLE_LEN,
};
use super::coverage::uncovered_contact_fields;
use super::guards::{js_safe_uint, js_uint, json_hex};
use super::sanitise::{sanitize_json_text, sanitize_wire_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Kin,
    Kith,
    Ken,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TierSource {
    Direct,
    GuardianVouched,
    GuardianLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verification {
    Unverified,
    Proven,
    Mutual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MethodKind {
    Phone,
    Email,
    Website,
    PostalAddress,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckMethod {
    Words,
    InPerson,
    Nip05,
    AppAttested,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactMethod {
    pub kind: MethodKind,
    pub value: String,
    /// `unverified` or `proven` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRecord {
    pub pubkey: String,
    pub method: CheckMethod,
    /// Unix MILLISECONDS.
    pub checked_at: u64,
}

/// One projected contact. `type`, `avatar` and `linkedPubkeys` are absent by
/// construction: no capability covers them, so a projection carrying any of
/// them is refused before a contact is built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedContact {
    pub contact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities: Option<Vec<Identity>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_tier: Option<Tier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_source: Option<TierSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_methods: Option<Vec<ContactMethod>>,
    /// Kept when `false` too (it is on the wire and covered).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<CheckRecord>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frontier {
    pub max_clock: u64,
    pub op_count: u64,
    pub published_at: u64,
    pub device_id: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A parsed, sanitised projection. There is no owner pubkey on this wire
/// (R-31); one a producer adds is dropped. The caller MUST still check
/// `grant_id` equals its grant's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Projection {
    pub v: u8,
    pub grant_id: String,
    pub scopes: Vec<Capability>,
    pub frontier: Frontier,
    pub issued_at: u64,
    pub expires_at: u64,
    pub contacts: Vec<ProjectedContact>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

/// Parse a projection body against the grant it arrived on. `None` when the
/// body is malformed, when any contact carries a field its scopes do not
/// cover, when its scopes exceed `granted`, or when its staleness window
/// (`expiresAt − issuedAt`) exceeds `max_staleness_seconds`.
pub fn parse_projection(body: &str, granted: &[Capability], max_staleness_seconds: u64) -> Option<Projection> {
    let p = parse_projection_body(body)?;
    if p.scopes.iter().any(|s| !granted.contains(s)) {
        return None;
    }
    if p.expires_at - p.issued_at > max_staleness_seconds {
        return None;
    }
    Some(p)
}

/// Upstream `parseProjection` alone, without the grant gates.
pub fn parse_projection_body(body: &str) -> Option<Projection> {
    let raw: Value = serde_json::from_str(body).ok()?;
    let o = raw.as_object()?;
    if js_uint(o.get("v")) != Some(2) {
        return None;
    }
    let grant_id = json_hex(o.get("grantId"), 32)?;
    let raw_scopes = o.get("scopes")?.as_array()?;
    let issued_at = js_uint(o.get("issuedAt"))?;
    let expires_at = js_uint(o.get("expiresAt")).filter(|e| *e >= issued_at)?;
    let f = o.get("frontier")?.as_object()?;
    let frontier = Frontier {
        max_clock: js_uint(f.get("maxClock"))?,
        op_count: js_uint(f.get("opCount"))?,
        published_at: js_uint(f.get("publishedAt"))?,
        device_id: json_hex(f.get("deviceId"), 32)?.to_owned(),
    };
    let raw_contacts = o.get("contacts")?.as_array()?;

    // Cap before filtering, like every array on this wire.
    let known: Vec<Capability> = raw_scopes
        .iter()
        .take(MAX_CAPABILITIES)
        .filter_map(|c| c.as_str().and_then(Capability::parse))
        .collect();
    let scopes = normalise_capabilities(&known);

    // A cut the reader makes is a truncation too (M8).
    let parser_capped = raw_contacts.len() > MAX_CONTACTS_PER_PROJECTION;
    let delivered = &raw_contacts[..raw_contacts.len().min(MAX_CONTACTS_PER_PROJECTION)];
    // Consent (§10): an uncovered field anywhere refuses the whole projection.
    if delivered.iter().any(|c| !uncovered_contact_fields(c, &scopes).is_empty()) {
        return None;
    }
    let mut contacts: Vec<ProjectedContact> = Vec::new();
    for c in delivered {
        if let Some(contact) = parse_contact(c) {
            // A later duplicate contactId is dropped; the first is kept.
            if !contacts.iter().any(|k| k.contact_id == contact.contact_id) {
                contacts.push(contact);
            }
        }
    }

    Some(Projection {
        v: 2,
        grant_id: grant_id.to_owned(),
        scopes,
        frontier,
        issued_at,
        expires_at,
        contacts,
        revoked: o.get("revoked") == Some(&Value::Bool(true)),
        truncated: o.get("truncated") == Some(&Value::Bool(true)) || parser_capped,
    })
}

/// Parse an enum from a present-but-optional JSON field: absent → `Ok(None)`,
/// present and valid → `Ok(Some)`, present and invalid (incl. `null`) → `Err`.
fn optional_enum<T: serde::de::DeserializeOwned>(o: &Map<String, Value>, key: &str) -> Result<Option<T>, ()> {
    match o.get(key) {
        None => Ok(None),
        Some(v) if v.is_string() => serde_json::from_value(v.clone()).map(Some).map_err(|_| ()),
        Some(_) => Err(()),
    }
}

/// `parseProjectedContact`, after the coverage check has already passed.
/// `None` when the contact cannot be trusted at all.
fn parse_contact(raw: &Value) -> Option<ProjectedContact> {
    let o = raw.as_object()?;
    let contact_id = json_hex(o.get("contactId"), 32)?;
    let effective_tier = optional_enum::<Tier>(o, "effectiveTier").ok()?;
    let tier_source = optional_enum::<TierSource>(o, "tierSource").ok()?;
    let blocked = match o.get("blocked") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return None,
    };
    let mut c = ProjectedContact {
        contact_id: contact_id.to_owned(),
        identities: None,
        display_name: None,
        effective_tier,
        tier_source,
        roles: None,
        contact_methods: None,
        blocked,
        checks: None,
    };
    if let Some(ids) = o.get("identities").and_then(Value::as_array) {
        let ids: Vec<Identity> = ids.iter().take(MAX_IDENTITIES_PER_CONTACT).filter_map(parse_identity).collect();
        c.identities = (!ids.is_empty()).then_some(ids);
    }
    if let Some(name) = o.get("displayName").and_then(Value::as_str) {
        let name = sanitize_wire_text(name, MAX_DISPLAY_NAME);
        c.display_name = (!name.is_empty()).then_some(name);
    }
    if let Some(roles) = o.get("roles").and_then(Value::as_array) {
        let roles: Vec<String> = roles
            .iter()
            .take(MAX_ROLES_PER_CONTACT)
            .map(|r| sanitize_json_text(Some(r), MAX_ROLE_LEN))
            .filter(|r| !r.is_empty())
            .collect();
        c.roles = (!roles.is_empty()).then_some(roles);
    }
    if let Some(methods) = o.get("contactMethods").and_then(Value::as_array) {
        let methods: Vec<ContactMethod> = methods.iter().take(MAX_METHODS_PER_CONTACT).filter_map(parse_method).collect();
        c.contact_methods = (!methods.is_empty()).then_some(methods);
    }
    if let Some(checks) = o.get("checks").and_then(Value::as_array) {
        let checks: Vec<CheckRecord> = checks.iter().take(MAX_CHECKS_PER_CONTACT).filter_map(parse_check).collect();
        c.checks = (!checks.is_empty()).then_some(checks);
    }
    Some(c)
}

fn parse_identity(raw: &Value) -> Option<Identity> {
    let o = raw.as_object()?;
    let pubkey = json_hex(o.get("pubkey"), 64)?;
    let verification = optional_enum::<Verification>(o, "verification").ok()?;
    Some(Identity { pubkey: pubkey.to_owned(), verification })
}

fn parse_method(raw: &Value) -> Option<ContactMethod> {
    let o = raw.as_object()?;
    let kind = optional_enum::<MethodKind>(o, "kind").ok()??;
    let value = sanitize_json_text(o.get("value"), MAX_METHOD_VALUE);
    if value.is_empty() {
        return None;
    }
    let verification = match optional_enum::<Verification>(o, "verification").ok()? {
        Some(Verification::Mutual) => return None,
        v => v,
    };
    Some(ContactMethod { kind, value, verification })
}

fn parse_check(raw: &Value) -> Option<CheckRecord> {
    let o = raw.as_object()?;
    let pubkey = json_hex(o.get("pubkey"), 64)?;
    let method = optional_enum::<CheckMethod>(o, "method").ok()??;
    let checked_at = js_safe_uint(o.get("checkedAt"))?;
    Some(CheckRecord { pubkey: pubkey.to_owned(), method, checked_at })
}

/// Strict frontier order (R-30): `publishedAt` first, `maxClock` breaks a
/// same-second tie, an exact tie on both is NOT newer.
pub fn frontier_newer(a: &Frontier, b: &Frontier) -> bool {
    (a.published_at, a.max_clock) > (b.published_at, b.max_clock)
}

/// Whether `incoming` should replace `held`. A revocation is exempt from the
/// order (losing one is worse than applying it out of order); everything else
/// must be strictly newer by [`frontier_newer`].
pub fn is_newer(incoming: &Projection, held: &Projection) -> bool {
    incoming.revoked || frontier_newer(&incoming.frontier, &held.frontier)
}
