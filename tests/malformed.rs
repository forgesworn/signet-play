//! Malformed input never panics and never gets through (fuzz-ish loops with a
//! fixed-seed PRNG, so failures reproduce).

mod support;

use std::time::Duration;

use decented_signet::attestation::{
    unsigned_attestation, verify_attestation, verify_attestation_event,
};
use decented_signet::contacts::{
    Grant, REQUESTED_CAPABILITIES, accept_projection, open_projection,
};
use decented_signet::contacts_wire::{decrypt_ack_event, projection_tag};
use decented_signet::invite::{INVITE_RUMOR_KIND, open_invite};
use decented_signet::relay::{Connector, FakeNetwork};
use decented_signet::{InvitePayload, SignInEvent};
use nostr::nips::nip44;
use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
use serde_json::{Value, json};
use support::*;

const T: Duration = Duration::from_secs(10);

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// Never empty (NIP-44 refuses to encrypt an empty string).
    fn text(&mut self) -> String {
        const PIECES: [&str; 14] = [
            "{", "}", "[", "]", "\"", ":", ",", "null", "1e999", "-1", "\u{202e}", "a", "\\u0000",
            "v",
        ];
        let n = 1 + self.below(40);
        (0..n).map(|_| PIECES[self.below(PIECES.len())]).collect()
    }
    /// Mutate a JSON string: flip, delete, insert or truncate.
    fn mutate(&mut self, s: &str) -> Vec<u8> {
        let mut b = s.as_bytes().to_vec();
        for _ in 0..1 + self.below(4) {
            if b.is_empty() {
                break;
            }
            let i = self.below(b.len());
            match self.below(4) {
                0 => b[i] ^= 1 << self.below(8),
                1 => {
                    b.remove(i);
                }
                2 => b.insert(i, self.next() as u8),
                _ => b.truncate(i),
            }
        }
        b
    }
}

fn random_json_value(r: &mut Rng, depth: u32) -> Value {
    match r.below(if depth > 2 { 5 } else { 7 }) {
        0 => Value::Null,
        1 => json!(r.next().is_multiple_of(3)),
        2 => json!(r.next() as i64),
        3 => json!(r.text()),
        4 => json!(-1.5e300),
        5 => Value::Array(
            (0..r.below(4))
                .map(|_| random_json_value(r, depth + 1))
                .collect(),
        ),
        _ => {
            let keys = [
                "v",
                "host_name",
                "code",
                "token",
                "expires_at",
                "attestation",
                "grantId",
                "contacts",
            ];
            let mut m = serde_json::Map::new();
            for _ in 0..r.below(6) {
                m.insert(
                    keys[r.below(keys.len())].into(),
                    random_json_value(r, depth + 1),
                );
            }
            Value::Object(m)
        }
    }
}

#[test]
fn attestation_parser_survives_garbage_and_mutations() {
    let mut r = Rng(0x5eed_0001);
    let persona = Keys::generate();
    let runtime = Keys::generate().public_key();
    let good = unsigned_attestation(APP_ID, &persona.public_key(), &runtime, now())
        .sign_with_keys(&persona)
        .unwrap();
    let good_json = serde_json::to_string(&good).unwrap();
    assert!(verify_attestation(APP_ID, &good_json, &runtime, now()).is_ok());
    for _ in 0..2000 {
        let n = r.below(300);
        let _ = verify_attestation(APP_ID, r.bytes(n), &runtime, now());
        let m = r.mutate(&good_json);
        if let Ok(info) = verify_attestation(APP_ID, &m, &runtime, now()) {
            // Only whitespace-level or no-op mutations may still verify.
            assert_eq!(info.persona, persona.public_key());
        }
        let _ = verify_attestation(APP_ID, r.text(), &runtime, now());
        let _ = verify_attestation(
            APP_ID,
            random_json_value(&mut r, 0).to_string(),
            &runtime,
            now(),
        );
    }
    // Hand-made events with odd tags (all signed, so only the checks reject).
    for _ in 0..300 {
        let tags: Vec<Tag> = (0..r.below(8))
            .filter_map(|_| {
                let names = [
                    "d",
                    "p",
                    "valid_from",
                    "valid_until",
                    "v",
                    "role",
                    "expiration",
                    "x",
                ];
                let vals = [
                    "twangthang".to_string(),
                    runtime.to_hex(),
                    "1".into(),
                    "player".into(),
                    u64::MAX.to_string(),
                    "-5".into(),
                    r.text(),
                    now().to_string(),
                ];
                Tag::parse([
                    names[r.below(names.len())].to_string(),
                    vals[r.below(vals.len())].clone(),
                ])
                .ok()
            })
            .collect();
        let ev = EventBuilder::new(Kind::Custom(30420), r.text())
            .tags(tags)
            .sign_with_keys(&persona)
            .unwrap();
        let _ = verify_attestation_event(APP_ID, &ev, &runtime, now());
    }
}

fn wrap_with_rumor(
    r: &mut Rng,
    sender: &Keys,
    to: &nostr::PublicKey,
    rt: &tokio::runtime::Runtime,
) -> Event {
    let kind = if r.below(3) == 0 {
        1
    } else {
        INVITE_RUMOR_KIND
    };
    let content = match r.below(3) {
        0 => r.text(),
        1 => random_json_value(r, 0).to_string(),
        _ => json!({
            "v": 2, "host_name": r.text(), "code": r.text(),
            "expires_at": r.next(), "attestation": r.text()
        })
        .to_string(),
    };
    let rumor = EventBuilder::new(Kind::Custom(kind), content).build(sender.public_key());
    rt.block_on(EventBuilder::gift_wrap(sender, to, rumor, []))
        .unwrap()
}

#[test]
fn invite_opener_survives_garbage() {
    let mut r = Rng(0x5eed_0002);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let me = Keys::generate();
    let junk_key = Keys::generate();
    for i in 0..300 {
        // Garbage content under a valid outer signature, addressed to us.
        let content = if i % 2 == 0 {
            r.text()
        } else {
            nip44::encrypt(
                junk_key.secret_key(),
                &me.public_key(),
                r.text(),
                nip44::Version::V2,
            )
            .unwrap()
        };
        let ev = EventBuilder::new(Kind::GiftWrap, content)
            .tag(Tag::public_key(me.public_key()))
            .sign_with_keys(&junk_key)
            .unwrap();
        assert!(rt.block_on(open_invite(&me, &ev, now())).is_err());
        // Well-formed wrap + seal, junk rumor.
        let w = wrap_with_rumor(&mut r, &junk_key, &me.public_key(), &rt);
        assert!(rt.block_on(open_invite(&me, &w, now())).is_err());
    }
}

#[test]
fn contacts_wire_survives_garbage() {
    let mut r = Rng(0x5eed_0003);
    let app = Keys::generate();
    let rail = Keys::generate();
    let grant_id = "1".repeat(32);
    let grant = Grant {
        v: 1,
        app_secret_hex: app.secret_key().to_secret_hex(),
        grant_id: grant_id.clone(),
        rail_pubkey: rail.public_key().to_hex(),
        projection_tag: projection_tag(&grant_id),
        relay: RELAY.into(),
        granted_capabilities: REQUESTED_CAPABILITIES.to_vec(),
        max_staleness_seconds: 21_600,
        paired_at: 0,
        persona: None,
    };
    let challenge = "a".repeat(32);
    for i in 0..300 {
        let plaintext = if i % 2 == 0 {
            r.text()
        } else {
            random_json_value(&mut r, 0).to_string()
        };
        let ct = nip44::encrypt(
            rail.secret_key(),
            &app.public_key(),
            &plaintext,
            nip44::Version::V2,
        )
        .unwrap();
        let content = if i % 3 == 0 { r.text() } else { ct };
        let ack = EventBuilder::new(Kind::Custom(21237), content.clone())
            .sign_with_keys(&rail)
            .unwrap();
        assert!(decrypt_ack_event(&ack, &app, &challenge, &REQUESTED_CAPABILITIES).is_none());
        let env = json!({"v": 2, "k": content, "iv": r.text(), "ct": r.text(), "b": r.next()})
            .to_string();
        let proj = EventBuilder::new(Kind::Custom(30078), if i % 2 == 0 { env } else { r.text() })
            .tag(Tag::identifier(projection_tag(&grant_id)))
            .custom_created_at(Timestamp::from(now()))
            .sign_with_keys(&rail)
            .unwrap();
        assert!(open_projection(&proj, &grant).is_none());
        let _ = accept_projection(&[proj], &grant, None);
    }
}

#[test]
fn junk_on_the_wire_does_not_break_sign_in_or_the_inbox() {
    let net = FakeNetwork::new();
    let mut r = Rng(0x5eed_0004);
    let persona = Keys::generate();
    let signer = FakeMySignet::new(&net, persona.clone());
    // Junk kind 0 for the persona: the profile fetch must shrug it off.
    for _ in 0..20 {
        publish_profile(&net, &persona, &r.text());
    }
    let dir = temp_dir("junk");
    let runtime = Keys::generate();
    let s = open(&net, &dir, &runtime);
    let si = s.sign_in();
    // Flood the app key with junk kind 24133 before the real reply.
    let uri = si.nostrconnect_uri().to_string();
    let app = nostr::PublicKey::from_hex(
        uri.trim_start_matches("nostrconnect://")
            .split('?')
            .next()
            .unwrap(),
    )
    .unwrap();
    let relay = net.connect(&[RELAY.to_string()]);
    let junk = Keys::generate();
    for i in 0..50 {
        let content = if i % 2 == 0 {
            r.text()
        } else {
            nip44::encrypt(
                junk.secret_key(),
                &app,
                random_json_value(&mut r, 0).to_string(),
                nip44::Version::V2,
            )
            .unwrap()
        };
        let ev = EventBuilder::new(Kind::NostrConnect, content)
            .tag(Tag::public_key(app))
            .sign_with_keys(&junk)
            .unwrap();
        relay.publish(&ev);
    }
    signer.handle_nostrconnect(&uri);
    let events = drain_sign_in(&si, T);
    assert!(
        matches!(events.last(), Some(SignInEvent::Attested { .. })),
        "{events:?}"
    );
    let _ = s.refresh_profile().wait(T);

    // Junk gift wraps to our runtime key: nothing comes out, a real one still does.
    let inbox = s.inbox();
    let rt = tokio::runtime::Runtime::new().unwrap();
    for _ in 0..50 {
        let w = wrap_with_rumor(&mut r, &junk, &runtime.public_key(), &rt);
        relay.publish(&w);
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(inbox.poll().is_none());
    // A real sender.
    let other_persona = Keys::generate();
    let other_rt = Keys::generate();
    let att = unsigned_attestation(
        APP_ID,
        &other_persona.public_key(),
        &other_rt.public_key(),
        now(),
    )
    .sign_with_keys(&other_persona)
    .unwrap();
    // We have played with them.
    s.played_with()
        .unwrap()
        .record(
            &serde_json::to_string(&att).unwrap(),
            &other_rt.public_key(),
            "Real",
            &[],
            now(),
        )
        .unwrap();
    let p = InvitePayload {
        host_name: "Real".into(),
        code: "XYZNPQ".into(),
        expires_at: now() + 60,
    };
    let wrap = rt
        .block_on(decented_signet::invite::wrap_invite(
            &other_rt,
            &serde_json::to_string(&att).unwrap(),
            &runtime.public_key(),
            &p,
        ))
        .unwrap();
    relay.publish(&wrap);
    let inv = wait_for(T, "real invite", || inbox.poll());
    assert_eq!(inv.payload, p);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn damaged_files_on_disk_are_survived() {
    let net = FakeNetwork::new();
    let dir = temp_dir("damaged");
    std::fs::create_dir_all(dir.join("signet")).unwrap();
    for f in [
        "session.json",
        "attestation.json",
        "profile.json",
        "contacts-grant.json",
        "contacts.json",
        "kept-blocks.json",
        "runtime-keys.json",
        "old-public-notes.json",
    ] {
        std::fs::write(dir.join("signet").join(f), b"{\"truncated\": ").unwrap();
    }
    let runtime = Keys::generate();
    let s = open(&net, &dir, &runtime);
    assert!(!s.is_signed_in());
    assert!(s.contacts().is_empty());
    assert!(s.played_with().is_none());
    assert!(s.old_public_note_personas().is_empty());
    // A used-keys list that cannot be read cannot say this key is new: not
    // knowing counts as used, and it is rewritten at once so a relaunch agrees.
    assert!(s.runtime_key_used());
    assert!(open(&net, &dir, &runtime).runtime_key_used());
    // The inbox of a signed-out install is closed, not a panic.
    assert!(s.inbox().poll().is_none());
    let _ = std::fs::remove_dir_all(dir);
}
