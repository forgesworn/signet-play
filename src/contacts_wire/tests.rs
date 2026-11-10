//! Conformance tests against the frozen upstream vectors (`vectors/`, upstream
//! fbb13cd). Every vector case is asserted; refusal cases fail loudly with the
//! vector's own `reason`.

use nostr::{EventBuilder, Keys, Kind, SecretKey, Tag};
use serde_json::{json, Value};

use super::constants::Capability::{self, *};
use super::envelope::{parse_vault_envelope, unpad};
use super::projection::parse_projection_body;
use super::*;

const PAIRING: &str = include_str!("vectors/pairing.v2.json");
const CODES: &str = include_str!("vectors/pairing-code.json");
const ENVELOPE: &str = include_str!("vectors/envelope.v2.json");
const PROJECTION: &str = include_str!("vectors/projection.v2.json");
const SANITISE: &str = include_str!("vectors/sanitise.json");

fn v(src: &str) -> Value {
    serde_json::from_str(src).expect("vector is valid JSON")
}
fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter().fold(v, |v, k| &v[*k]).as_str().unwrap_or_else(|| panic!("vector field {path:?}"))
}

const APP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHALLENGE: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
const RELAY: &str = "wss://relay.example.com";
const REQUESTED: [Capability; 3] = [ReadDirectory, BlocksRead, ProposeAddKen];

// ---------- pairing URI (pairing.v2.json) ----------

#[test]
fn pairing_uri_is_byte_exact_and_order_independent() {
    let vec = v(PAIRING);
    let t = vec["nowSec"].as_u64().unwrap();
    let shuffled = [ProposeAddKen, ReadDirectory, BlocksRead, ReadDirectory];
    let uri = build_pairing_uri(APP, "Flock", &shuffled, Directory::Owner, RELAY, t, CHALLENGE).unwrap();
    assert_eq!(uri, s(&vec, &["request", "uri"]));
    let parsed = &vec["request"]["parsed"];
    assert_eq!(s(parsed, &["appPubkey"]), APP);
    assert_eq!(s(parsed, &["challenge"]), CHALLENGE);
}

#[test]
fn web_carrier_keeps_the_query_string() {
    let uri = s(&v(PAIRING), &["request", "uri"]).to_owned();
    let web = web_carrier("mysignet.app", &uri);
    let query = uri.split_once('?').unwrap().1;
    assert_eq!(web, format!("https://mysignet.app/?pair=1&{query}"));
    assert!(web.starts_with("https://mysignet.app/?pair=1&v=2&app="));
}

#[test]
fn pairing_uri_form_encodes_like_url_search_params() {
    let uri = build_pairing_uri(APP, "Example Game", &[ReadDirectory], Directory::Dependant, "ws://localhost:7777", 5, &"ab".repeat(16)).unwrap();
    assert!(uri.contains("&name=Example+Game&"), "{uri}");
    assert!(uri.contains("&dir=dependant&relay=ws%3A%2F%2Flocalhost%3A7777&t=5&"), "{uri}");
}

#[test]
fn pairing_uri_builder_refuses_bad_input() {
    let ok = |app: &str, name: &str, caps: &[Capability], relay: &str, ch: &str| {
        build_pairing_uri(app, name, caps, Directory::Owner, relay, 1, ch)
    };
    assert_eq!(ok(&APP.to_uppercase(), "A", &REQUESTED, RELAY, CHALLENGE), Err(PairingError::AppPubkey));
    assert_eq!(ok(APP, "", &REQUESTED, RELAY, CHALLENGE), Err(PairingError::AppName));
    assert_eq!(ok(APP, "a\nb", &REQUESTED, RELAY, CHALLENGE), Err(PairingError::AppName));
    assert_eq!(ok(APP, &"x".repeat(65), &REQUESTED, RELAY, CHALLENGE), Err(PairingError::AppName));
    assert_eq!(ok(APP, "A", &[], RELAY, CHALLENGE), Err(PairingError::NoCapabilities));
    assert_eq!(ok(APP, "A", &REQUESTED, "https://relay.example.com", CHALLENGE), Err(PairingError::Relay));
    assert_eq!(ok(APP, "A", &REQUESTED, "ws://relay.example.com", CHALLENGE), Err(PairingError::Relay));
    assert_eq!(ok(APP, "A", &REQUESTED, "ws://localhostevil.com", CHALLENGE), Err(PairingError::Relay));
    let long = format!("wss://{}", "r".repeat(251));
    assert_eq!(ok(APP, "A", &REQUESTED, &long, CHALLENGE), Err(PairingError::Relay));
    assert!(ok(APP, "A", &REQUESTED, &long[..256], CHALLENGE).is_ok());
    assert!(ok(APP, "A", &REQUESTED, "WSS://Relay.example.com", CHALLENGE).is_ok());
    assert_eq!(ok(APP, "A", &REQUESTED, RELAY, &CHALLENGE[..31]), Err(PairingError::Challenge));
    assert_eq!(ok(APP, "A", &REQUESTED, RELAY, &"g".repeat(32)), Err(PairingError::Challenge));
}

// ---------- §4 tags ----------

#[test]
fn tags_match_the_vector() {
    let vec = v(PAIRING);
    let grant = s(&vec, &["ack", "parsed", "grantId"]);
    assert_eq!(projection_tag(grant), s(&vec, &["tags", "projectionTag"]));
    assert_eq!(proposal_tag(grant, APP), s(&vec, &["tags", "proposalTag"]));
    assert_eq!(ack_tag(CHALLENGE), s(&vec, &["tags", "ackTag"]));
    assert_eq!(ack_tag(&CHALLENGE.to_lowercase()), s(&vec, &["tags", "ackTag"]));
}

#[test]
fn scoped_contact_id_mixes_lengths() {
    // References computed independently with `sha256sum` over the §4 payload.
    assert_eq!(scoped_contact_id("ab", "c:d"), "93be9bdca00758cf1194dc14c9201ae9");
    assert_eq!(scoped_contact_id("ab:c", "d"), "7fb99d555d39bd22076407d71b8d697a");
}

// ---------- ack (pairing.v2.json) ----------

#[test]
fn ack_vector_parses_exactly() {
    let vec = v(PAIRING);
    let ack = parse_ack(s(&vec, &["ack", "plaintext"]), CHALLENGE, &REQUESTED).expect("vector ack");
    assert_eq!(serde_json::to_value(&ack).unwrap(), vec["ack"]["parsed"]);
}

#[test]
fn ack_refusals() {
    let vec = v(PAIRING);
    let pt = s(&vec, &["ack", "plaintext"]);
    assert!(parse_ack(pt, s(&vec, &["ack", "wrongChallenge"]), &REQUESTED).is_none(), "wrong challenge");
    assert!(parse_ack(pt, &CHALLENGE.to_lowercase(), &REQUESTED).is_none(), "challenge is case-preserved");
    assert!(parse_ack(s(&vec, &["ack", "v1Plaintext"]), CHALLENGE, &REQUESTED).is_none(), "v1 ack");
    assert!(parse_ack(pt, CHALLENGE, &[ReadDirectory]).is_none(), "wider than requested");
    assert!(parse_ack("not json", CHALLENGE, &REQUESTED).is_none());
    assert!(parse_ack("[]", CHALLENGE, &REQUESTED).is_none());
}

fn ack_json(edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> String {
    let mut o = v(s(&v(PAIRING), &["ack", "plaintext"])).as_object().unwrap().clone();
    edit(&mut o);
    Value::Object(o).to_string()
}

#[test]
fn ack_field_rules() {
    let parse = |j: String| parse_ack(&j, CHALLENGE, &REQUESTED);
    // Unknown tokens dropped; none known → refused.
    let a = parse(ack_json(|o| { o.insert("grantedCapabilities".into(), json!(["x", "signet.contacts.blocks.read", "signet.contacts.read:methods"])); })).unwrap();
    assert_eq!(a.granted_capabilities, vec![BlocksRead]);
    assert!(parse(ack_json(|o| { o.insert("grantedCapabilities".into(), json!(["x"])); })).is_none());
    // Staleness clamp.
    for (input, want) in [(json!(10), 3600), (json!(1e9), 604800), (json!(-5), 21600), (json!(7200.9), 7200), (json!("7200"), 21600)] {
        let a = parse(ack_json(|o| { o.insert("maxStalenessSeconds".into(), input.clone()); })).unwrap();
        assert_eq!(a.max_staleness_seconds, want, "clamp {input}");
    }
    assert_eq!(parse(ack_json(|o| { o.remove("maxStalenessSeconds"); })).unwrap().max_staleness_seconds, 21600);
    // Ids and relay.
    assert!(parse(ack_json(|o| { o.insert("grantId".into(), json!("F".repeat(32))); })).is_none());
    assert!(parse(ack_json(|o| { o.insert("railPubkey".into(), json!("b".repeat(62))); })).is_none());
    assert!(parse(ack_json(|o| { o.insert("relay".into(), json!("ws://relay.example.com")); })).is_none());
    assert!(parse(ack_json(|o| { o.insert("v".into(), json!(3)); })).is_none());
    assert!(parse(ack_json(|o| { o.insert("v".into(), json!(2.0)); })).is_some());
}

fn ack_event(kind: u16, plaintext: &str, to: &Keys) -> nostr::Event {
    let ephemeral = Keys::generate();
    let ct = nostr::nips::nip44::encrypt(ephemeral.secret_key(), &to.public_key(), plaintext, nostr::nips::nip44::Version::V2).unwrap();
    EventBuilder::new(Kind::Custom(kind), ct)
        .tags([Tag::public_key(to.public_key())])
        .sign_with_keys(&ephemeral)
        .unwrap()
}

#[test]
fn decrypt_ack_event_gates() {
    let app = Keys::generate();
    let pt = s(&v(PAIRING), &["ack", "plaintext"]).to_owned();
    let want = parse_ack(&pt, CHALLENGE, &REQUESTED).unwrap();
    assert_eq!(decrypt_ack_event(&ack_event(21237, &pt, &app), &app, CHALLENGE, &REQUESTED), Some(want.clone()));
    assert_eq!(decrypt_ack_event(&ack_event(30078, &pt, &app), &app, CHALLENGE, &REQUESTED), Some(want));
    assert!(decrypt_ack_event(&ack_event(1, &pt, &app), &app, CHALLENGE, &REQUESTED).is_none(), "wrong kind");
    let other = Keys::generate();
    assert!(decrypt_ack_event(&ack_event(21237, &pt, &other), &app, CHALLENGE, &REQUESTED).is_none(), "not to us");
    let self_rail = ack_json(|o| { o.insert("railPubkey".into(), json!(app.public_key().to_hex())); });
    assert!(decrypt_ack_event(&ack_event(21237, &self_rail, &app), &app, CHALLENGE, &REQUESTED).is_none(), "self rail");
    assert!(ack_event_is_fresh(1000, 1300) && ack_event_is_fresh(1300, 1000));
    assert!(!ack_event_is_fresh(1000, 1301) && !ack_event_is_fresh(1301, 1000));
}

// ---------- pairing code (pairing-code.json) ----------

#[test]
fn pairing_code_vectors() {
    let vec = v(CODES);
    let cases = vec["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for c in cases {
        let i = &c["input"];
        let code = pairing_code(s(i, &["appPubkey"]), s(i, &["challenge"]), s(i, &["grantId"]), s(i, &["railPubkey"]));
        assert_eq!(code.as_deref(), Some(s(c, &["code"])), "{}", s(c, &["description"]));
    }
    assert_eq!(format_pairing_code("082705"), "082 705");
    assert_eq!(format_pairing_code("112464"), "112 464");
    let b = "b".repeat(64);
    assert!(pairing_code(APP, CHALLENGE, &"F".repeat(32), &b).is_none());
    assert!(pairing_code(APP, &CHALLENGE[..30], &"f".repeat(32), &b).is_none());
}

// ---------- vault envelope (envelope.v2.json) ----------

fn sk(hex: &str) -> SecretKey {
    SecretKey::from_hex(hex).unwrap()
}

#[test]
fn envelope_vector_opens() {
    let vec = v(ENVELOPE);
    let app = sk(s(&vec, &["appSecretKey"]));
    let rail = Keys::new(sk(s(&vec, &["railSecretKey"])));
    assert_eq!(rail.public_key().to_hex(), s(&vec, &["railPubkey"]));
    assert_eq!(Keys::new(app.clone()).public_key().to_hex(), s(&vec, &["appPubkey"]));
    let sealed = s(&vec, &["sealed"]);
    let env = parse_vault_envelope(sealed).unwrap();
    assert_eq!(env.k, s(&vec, &["parsed", "k"]));
    assert_eq!(env.iv, s(&vec, &["parsed", "iv"]));
    assert_eq!(env.ct, s(&vec, &["parsed", "ct"]));
    assert_eq!(env.b as u64, vec["parsed"]["b"].as_u64().unwrap());
    let body = open_vault_envelope(sealed, &app, &rail.public_key()).expect("vector opens");
    assert_eq!(body, s(&vec, &["plaintext"]).as_bytes());
    assert_eq!(open_vault_envelope_text(sealed, &app, &rail.public_key()).as_deref(), Some(s(&vec, &["plaintext"])));
}

#[test]
fn envelope_failures_are_none() {
    let vec = v(ENVELOPE);
    let app = sk(s(&vec, &["appSecretKey"]));
    let rail = Keys::new(sk(s(&vec, &["railSecretKey"]))).public_key();
    let sealed = s(&vec, &["sealed"]);
    let edit = |f: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut o = v(sealed).as_object().unwrap().clone();
        f(&mut o);
        Value::Object(o).to_string()
    };
    let wrong = Keys::generate();
    assert!(open_vault_envelope(sealed, wrong.secret_key(), &rail).is_none(), "wrong app key");
    assert!(open_vault_envelope(sealed, &app, &wrong.public_key()).is_none(), "wrong rail");
    let ct = s(&vec, &["parsed", "ct"]);
    let flipped = format!("{}{}", if ct.starts_with('A') { "B" } else { "A" }, &ct[1..]);
    assert!(open_vault_envelope(&edit(&|o| { o.insert("ct".into(), json!(flipped)); }), &app, &rail).is_none(), "tampered ct");
    assert!(open_vault_envelope(&edit(&|o| { o.insert("b".into(), json!(8192)); }), &app, &rail).is_none(), "relabelled bucket");
    assert!(open_vault_envelope(&edit(&|o| { o.insert("b".into(), json!(4000)); }), &app, &rail).is_none(), "not a bucket");
    assert!(open_vault_envelope(&edit(&|o| { o.insert("v".into(), json!(1)); }), &app, &rail).is_none(), "v1");
    assert!(open_vault_envelope(&edit(&|o| { o.remove("iv"); }), &app, &rail).is_none(), "missing iv");
    assert!(open_vault_envelope(&edit(&|o| { o.insert("iv".into(), json!("AAAA")); }), &app, &rail).is_none(), "short iv");
    // A bare NIP-44 payload is never tried as a fallback.
    let rail_keys = Keys::new(sk(s(&vec, &["railSecretKey"])));
    let app_pk = Keys::new(app.clone()).public_key();
    let bare = nostr::nips::nip44::encrypt(rail_keys.secret_key(), &app_pk, s(&vec, &["plaintext"]), nostr::nips::nip44::Version::V2).unwrap();
    assert!(open_vault_envelope(&bare, &app, &rail).is_none(), "bare nip44");
    let huge = format!("{}{}", sealed, " ".repeat(100_001));
    assert!(open_vault_envelope(&huge, &app, &rail).is_none(), "oversize");
    assert!(unpad(&[0, 0, 0, 5, 1, 2, 3, 4]).is_none());
    assert_eq!(unpad(&[0, 0, 0, 2, 7, 8, 0, 0]), Some(&[7u8, 8][..]));
    assert!(unpad(&[0, 0, 1]).is_none());
}

// ---------- sanitiser (sanitise.json) ----------

#[test]
fn sanitise_vectors() {
    let vec = v(SANITISE);
    let max = vec["maxLen"].as_u64().unwrap() as usize;
    let pairs = vec["pairs"].as_array().unwrap();
    assert_eq!(pairs.len(), 12);
    for p in pairs {
        assert_eq!(sanitize_wire_text(s(p, &["input"]), max), s(p, &["output"]), "input {:?}", p["input"]);
    }
    assert_eq!(sanitize_wire_text("\u{feff} a \u{3000}", 10), "a", "JS trim set");
}

// ---------- projection (projection.v2.json) ----------

fn all() -> Vec<Capability> {
    Capability::ALL.to_vec()
}

#[test]
fn projection_vector_cases_parse_exactly() {
    let vec = v(PROJECTION);
    for case in ["full", "blocksOnly", "revocation", "truncated"] {
        let p = parse_projection(s(&vec, &[case, "plaintext"]), &all(), 21_600)
            .unwrap_or_else(|| panic!("{case} refused"));
        assert_eq!(serde_json::to_value(&p).unwrap(), vec[case]["parsed"], "{case}");
        // Round-trips through serde for storage.
        let back: Projection = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        assert_eq!(back, p, "{case} serde round-trip");
    }
}

#[test]
fn projection_malformed_cases() {
    let vec = v(PROJECTION);
    let m = vec["malformed"].as_array().unwrap();
    assert_eq!(m.len(), 4);
    for i in [0, 1, 3] {
        assert!(parse_projection_body(m[i].as_str().unwrap()).is_none(), "malformed[{i}] must be refused");
    }
    // R-31: an ownerPubkey is not fatal; it is simply not part of the wire.
    let p = parse_projection(m[2].as_str().unwrap(), &all(), 21_600).expect("ownerPubkey is dropped, not fatal");
    let out = serde_json::to_value(&p).unwrap();
    assert!(out.get("ownerPubkey").is_none());
    assert!(p.scopes.is_empty() && p.contacts.is_empty());
}

#[test]
fn projection_uncovered_cases_are_refused_whole() {
    let vec = v(PROJECTION);
    let cases = vec["uncovered"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for c in cases {
        let reason = s(c, &["reason"]);
        // Refused for the RIGHT reason: the coverage table flags the contact.
        let body = v(s(c, &["plaintext"]));
        let scopes: Vec<Capability> =
            body["scopes"].as_array().unwrap().iter().filter_map(|x| Capability::parse(x.as_str().unwrap())).collect();
        let flagged = super::coverage::uncovered_contact_fields(&body["contacts"][0], &scopes);
        assert!(!flagged.is_empty(), "coverage must flag: {reason}");
        assert!(parse_projection_body(s(c, &["plaintext"])).is_none(), "must refuse whole: {reason}");
        assert!(parse_projection(s(c, &["plaintext"]), &all(), MAX_STALE).is_none(), "must refuse whole: {reason}");
    }
}

const MAX_STALE: u64 = super::constants::MAX_STALENESS_SECONDS;

#[test]
fn projection_grant_gates() {
    let full = s(&v(PROJECTION), &["full", "plaintext"]).to_owned();
    assert!(parse_projection(&full, &[ReadDirectory, BlocksRead], MAX_STALE).is_none(), "scopes exceed grant");
    assert!(parse_projection(&full, &all(), 21_599).is_none(), "window exceeds grant staleness");
    assert!(parse_projection(&full, &all(), 21_600).is_some());
}

fn body(scopes: Value, contacts: Value) -> String {
    json!({
        "v": 2, "grantId": "f".repeat(32), "scopes": scopes,
        "frontier": {"maxClock": 1, "opCount": 1, "publishedAt": 1, "deviceId": "2".repeat(32)},
        "issuedAt": 1, "expiresAt": 2, "contacts": contacts,
    })
    .to_string()
}

fn cid(n: usize) -> String {
    format!("{n:032x}")
}

#[test]
fn projection_item_level_drops_and_caps() {
    let dir = json!(["signet.contacts.read:directory", "signet.contacts.read:tier"]);
    let contacts = json!([
        {"contactId": "short"},
        {"contactId": cid(1), "displayName": "  Ada\u{202e}  ", "identities": [{"pubkey": "x"}, {"pubkey": "c".repeat(64)}]},
        {"contactId": cid(1), "displayName": "Duplicate"},
        {"contactId": cid(2), "effectiveTier": null},
        {"contactId": cid(3), "effectiveTier": "stranger"},
        {"contactId": cid(4), "effectiveTier": "kin", "displayName": 7},
        42,
    ]);
    let p = parse_projection_body(&body(dir.clone(), contacts)).unwrap();
    let ids: Vec<&str> = p.contacts.iter().map(|c| c.contact_id.as_str()).collect();
    assert_eq!(ids, vec![cid(1).as_str(), cid(4).as_str()]);
    assert_eq!(p.contacts[0].display_name.as_deref(), Some("Ada"));
    assert_eq!(p.contacts[0].identities.as_ref().unwrap().len(), 1);
    assert_eq!(p.contacts[1].effective_tier, Some(Tier::Kin));
    assert!(p.contacts[1].display_name.is_none());
    assert!(!p.truncated);

    let many: Vec<Value> = (0..2001).map(|n| json!({"contactId": cid(n)})).collect();
    let p = parse_projection_body(&body(dir, Value::Array(many))).unwrap();
    assert_eq!(p.contacts.len(), 2000);
    assert!(p.truncated, "a parser cut sets truncated");
}

#[test]
fn projection_presence_rules() {
    let dir = json!(["signet.contacts.read:directory"]);
    let one = |c: Value| parse_projection_body(&body(dir.clone(), json!([c])));
    assert!(one(json!({"contactId": cid(1), "avatar": null})).is_none(), "null counts as present");
    assert!(one(json!({"contactId": cid(1), "type": "person"})).is_none(), "type never covered");
    assert!(one(json!({"contactId": cid(1), "linkedPubkeys": []})).is_none(), "linkedPubkeys never covered");
    assert!(one(json!({"contactId": cid(1), "contactMethods": [{"kind": "pager", "value": "1"}]})).is_none(), "unknown method kind");
    assert!(one(json!({"contactId": cid(1), "blocked": true})).is_none(), "blocked needs blocks.read");
    assert!(one(json!({"contactId": cid(1), "contactMethods": []})).is_some(), "empty methods array is covered by directory");
    // Blocks-only: a blocked contact with identities is fine, an array contact is not.
    let blocks = json!(["signet.contacts.blocks.read"]);
    let b = |c: Value| parse_projection_body(&body(blocks.clone(), json!([c])));
    assert!(b(json!({"contactId": cid(1), "blocked": true, "identities": [{"pubkey": "d".repeat(64)}]})).is_some());
    assert!(b(json!({"contactId": cid(1), "blocked": true, "displayName": "x"})).is_none());
    assert!(b(json!([])).is_none(), "an array contact is a JS object: uncovered under blocks-only");
    assert!(b(json!(7)).is_some(), "a scalar contact is dropped, not refused");
}

#[test]
fn projection_header_rules() {
    let p = |edit: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut o = v(&body(json!([]), json!([]))).as_object().unwrap().clone();
        edit(&mut o);
        parse_projection_body(&Value::Object(o).to_string())
    };
    assert!(p(&|_| {}).is_some());
    assert!(p(&|o| { o.insert("expiresAt".into(), json!(0)); }).is_none(), "expiresAt < issuedAt");
    assert!(p(&|o| { o.insert("issuedAt".into(), json!(-1)); }).is_none());
    assert!(p(&|o| { o.insert("issuedAt".into(), json!(1.5)); }).is_none());
    assert!(p(&|o| { o["frontier"]["deviceId"] = json!("2".repeat(31)); }).is_none());
    assert!(p(&|o| { o.remove("contacts"); }).is_none());
    let unknown = p(&|o| { o.insert("scopes".into(), json!(["nope", "signet.contacts.blocks.read", "signet.contacts.read:directory"])); }).unwrap();
    assert_eq!(unknown.scopes, vec![ReadDirectory, BlocksRead], "unknown dropped, normalised order");
    let flags = p(&|o| { o.insert("revoked".into(), json!("yes")); o.insert("truncated".into(), json!(true)); }).unwrap();
    assert!(!flags.revoked && flags.truncated, "only literal true counts");
}

// ---------- newest wins (R-30) ----------

#[test]
fn newest_wins_order() {
    let base = parse_projection_body(s(&v(PROJECTION), &["full", "plaintext"])).unwrap();
    let with = |published_at: u64, max_clock: u64, revoked: bool| {
        let mut p = base.clone();
        p.frontier.published_at = published_at;
        p.frontier.max_clock = max_clock;
        p.revoked = revoked;
        p
    };
    let held = with(100, 50, false);
    assert!(is_newer(&with(101, 0, false), &held), "publishedAt first");
    assert!(is_newer(&with(100, 51, false), &held), "maxClock breaks a tie");
    assert!(!is_newer(&with(100, 50, false), &held), "exact tie is not newer");
    assert!(!is_newer(&with(99, 999, false), &held), "older publishedAt loses whatever the clock");
    assert!(is_newer(&with(1, 0, true), &held), "revocation is exempt");
    assert!(frontier_newer(&with(2, 0, false).frontier, &with(1, 9, false).frontier));
}
