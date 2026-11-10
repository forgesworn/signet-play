//! Field coverage (WIRE.md §6 "Field coverage", §10) — which capability
//! unlocks which projected-contact field. Port of upstream `coverage.ts`.
//! A field is judged by its PRESENCE on the wire (a JSON `null` counts), not
//! by whether it would parse. Anything uncovered refuses the whole projection.

use serde_json::{Map, Value};

use super::constants::Capability::{self, *};
use super::guards::has;

/// `requires` (all-of), and for a contact carrying `blocked: true` only, an
/// alternative all-of list.
struct Rule {
    requires: &'static [Capability],
    or_if_blocked: Option<&'static [Capability]>,
}

const fn rule(requires: &'static [Capability]) -> Rule {
    Rule { requires, or_if_blocked: None }
}

/// `FIELD_COVERAGE`, keyed by field path. A path with no entry is covered by
/// nothing (e.g. an unknown method kind, `avatar`, `type`, `linkedPubkeys`).
fn rule_for(path: &str) -> Option<Rule> {
    Some(match path {
        "contact" | "identities" => Rule { requires: &[ReadDirectory], or_if_blocked: Some(&[BlocksRead]) },
        "identities[].verification" => rule(&[ReadDirectory, ReadChecks]),
        "displayName" => rule(&[ReadDirectory]),
        "effectiveTier" | "tierSource" => rule(&[ReadDirectory, ReadTier]),
        "roles" => rule(&[ReadDirectory, ReadRoles]),
        "contactMethods" => rule(&[ReadDirectory]),
        "contactMethods[kind=phone]" => rule(&[ReadDirectory, ReadMethodPhone]),
        "contactMethods[kind=email]" => rule(&[ReadDirectory, ReadMethodEmail]),
        "contactMethods[kind=website]" => rule(&[ReadDirectory, ReadMethodWebsite]),
        "contactMethods[kind=postal-address]" => rule(&[ReadDirectory, ReadMethodPostalAddress]),
        "contactMethods[kind=other]" => rule(&[ReadDirectory, ReadMethodOther]),
        "contactMethods[].verification" => rule(&[ReadDirectory, ReadChecks]),
        "checks" => rule(&[ReadDirectory, ReadCheckRecords]),
        "blocked" => rule(&[BlocksRead]),
        _ => return None,
    })
}

fn covered(path: &str, scopes: &[Capability], blocked: bool) -> bool {
    let Some(r) = rule_for(path) else { return false };
    if r.requires.iter().all(|c| scopes.contains(c)) {
        return true;
    }
    blocked && r.or_if_blocked.is_some_and(|alt| alt.iter().all(|c| scopes.contains(c)))
}

/// Contact-level keys no capability covers.
const NEVER_COVERED: [&str; 3] = ["avatar", "type", "linkedPubkeys"];

/// JavaScript `String(value)`, used to build the method-kind path exactly as
/// upstream does (so `["phone"]` stringifies to `phone`, like JS).
fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".to_owned(),
        Some(v) => js_string_value(v),
    }
}

fn js_string_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_owned(),
        Value::String(s) => s.clone(),
        Value::Object(_) => "[object Object]".to_owned(),
        Value::Array(items) => items
            .iter()
            .map(|i| if i.is_null() { String::new() } else { js_string_value(i) })
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

/// Field paths a RAW contact carries that `scopes` do not cover. Empty means
/// within the grant. A scalar/null contact yields nothing here (it is dropped
/// later as malformed, not refused). An ARRAY is a JS object with no wire
/// keys, so it is judged like `{}` — as upstream does.
pub fn uncovered_contact_fields(raw: &Value, scopes: &[Capability]) -> Vec<String> {
    let empty = Map::new();
    let o = match raw {
        Value::Object(o) => o,
        Value::Array(_) => &empty,
        _ => return Vec::new(),
    };
    let blocked = o.get("blocked") == Some(&Value::Bool(true));
    let mut out: Vec<String> = Vec::new();

    if !covered("contact", scopes, blocked) {
        out.push("contact".to_owned());
    }
    for key in ["identities", "displayName", "effectiveTier", "tierSource", "roles", "contactMethods", "checks", "blocked"] {
        if has(o, key) && !covered(key, scopes, blocked) {
            out.push(key.to_owned());
        }
    }
    for key in NEVER_COVERED {
        if has(o, key) {
            out.push(key.to_owned());
        }
    }
    check_identities(o, scopes, blocked, &mut out);
    check_methods(o, scopes, blocked, &mut out);
    out
}

fn check_identities(o: &Map<String, Value>, scopes: &[Capability], blocked: bool, out: &mut Vec<String>) {
    let Some(ids) = o.get("identities").and_then(Value::as_array) else { return };
    let verified = ids.iter().any(|i| i.as_object().is_some_and(|i| has(i, "verification")));
    if verified && !covered("identities[].verification", scopes, blocked) {
        out.push("identities[].verification".to_owned());
    }
}

fn check_methods(o: &Map<String, Value>, scopes: &[Capability], blocked: bool, out: &mut Vec<String>) {
    let Some(methods) = o.get("contactMethods").and_then(Value::as_array) else { return };
    let empty = Map::new();
    for m in methods {
        // An array entry is a JS object whose `kind` is undefined.
        let method = match m {
            Value::Object(o) => o,
            Value::Array(_) => &empty,
            _ => continue,
        };
        let path = format!("contactMethods[kind={}]", js_string(method.get("kind")));
        if !covered(&path, scopes, blocked) && !out.contains(&path) {
            out.push(path);
        }
        let vpath = "contactMethods[].verification";
        if has(method, "verification") && !covered(vpath, scopes, blocked) && !out.iter().any(|p| p == vpath) {
            out.push(vpath.to_owned());
        }
    }
}
