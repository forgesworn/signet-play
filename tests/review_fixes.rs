//! Regression tests from the independent reviews that still apply: shared
//! devices (sign-out separates personas), contacts pairing, blocks, and
//! sign-in dialogs. (The withdrawal and discoverability tests went with the
//! publishing they covered; see `invites.rs` and `old_notes.rs`.)

mod support;

use std::sync::Arc;
use std::time::Duration;

use decented_signet::relay::FakeNetwork;
use decented_signet::{ContactsSync, PairingEvent, SignInEvent, Signet, SignetConfig};
use nostr::Keys;
use serde_json::{Value, json};
use support::*;

const T: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(500);

fn signed_in(net: &FakeNetwork, dir: &std::path::Path, persona: &Keys) -> (Signet, FakeMySignet) {
    let s = open(net, dir, &Keys::generate());
    let signer = sign_in_as(net, &s, persona);
    (s, signer)
}

// ─── H1: shared device ──────────────────────────────────────────────────────

/// A signs out on the family tablet; sibling C gets nothing of A's.
#[test]
fn shared_device_sign_out_separates_personas() {
    let net = FakeNetwork::new();
    let alex = player(&net, "h1-alex");

    let dir = temp_dir("h1-tablet");
    let r1 = Keys::generate();
    let tablet = open(&net, &dir, &r1);
    let child_a = Keys::generate();
    let _sa = sign_in_as(&net, &tablet, &child_a);
    give_contacts(
        &net,
        &tablet,
        json!([contact(
            'a',
            &alex.persona.public_key(),
            "Alex P",
            "kin",
            false
        )]),
    );
    let a_book = tablet.played_with().unwrap();
    a_book
        .record(
            &alex.s.attestation_json().unwrap(),
            &alex.runtime.public_key(),
            "Alex P",
            &alex.s.inbox_relays(),
            now(),
        )
        .unwrap();
    assert_eq!(a_book.len(), 1);

    let outcome = tablet.sign_out();
    // Local state is gone before this returns.
    assert!(!tablet.is_signed_in());
    assert!(!tablet.has_contacts_grant());
    assert!(tablet.contacts().is_empty());
    assert!(tablet.runtime_key_retired());
    assert!(tablet.played_with().is_none());
    for f in [
        "session.json",
        "attestation.json",
        "contacts-grant.json",
        "contacts.json",
    ] {
        assert!(
            !dir.join("signet").join(f).exists(),
            "{f} survived sign-out"
        );
    }
    let outcome = outcome.wait(T).unwrap();
    assert!(
        outcome.signed_out && outcome.rotate_runtime_key,
        "{outcome:?}"
    );

    // The retired key refuses another persona, also after a restart.
    let refused = drain_sign_in(&tablet.sign_in(), T);
    assert!(
        matches!(refused.last(), Some(SignInEvent::Failed { .. })),
        "{refused:?}"
    );
    let reopened = open(&net, &dir, &r1);
    assert!(reopened.runtime_key_retired());
    assert!(matches!(
        drain_sign_in(&reopened.sign_in(), T).last(),
        Some(SignInEvent::Failed { .. })
    ));

    // The app rotates its key; C signs in with nothing of A's.
    let r2 = Keys::generate();
    let tablet2 = open(&net, &dir, &r2);
    assert!(!tablet2.runtime_key_retired());
    let child_c = Keys::generate();
    let sc = sign_in_as(&net, &tablet2, &child_c);
    assert!(!tablet2.has_contacts_grant());
    assert!(
        tablet2.played_with().unwrap().is_empty(),
        "C does not see who A played with"
    );
    // Alex has played with C, but C not with Alex, and A's Alex entry is not C's.
    let c = Player {
        s: tablet2,
        persona: child_c,
        runtime: r2,
        signer: sc,
        dir,
    };
    meet(&alex, &c, "C");
    let inbox = c.s.inbox();
    send(&alex, &c);
    std::thread::sleep(QUIET);
    assert!(inbox.poll().is_none(), "C has not played with Alex");
}

/// A persona's book stays on the phone for the next time that persona signs in.
#[test]
fn a_personas_book_survives_sign_out_and_a_new_install_key() {
    let net = FakeNetwork::new();
    let alex = player(&net, "h1b-alex");
    let dir = temp_dir("h1b-tablet");
    let persona = Keys::generate();
    let s1 = open(&net, &dir, &Keys::generate());
    let _sig1 = sign_in_as(&net, &s1, &persona);
    s1.played_with()
        .unwrap()
        .record(
            &alex.s.attestation_json().unwrap(),
            &alex.runtime.public_key(),
            "Alex",
            &alex.s.inbox_relays(),
            now(),
        )
        .unwrap();
    s1.sign_out().wait(T).unwrap();
    // The same persona, another install key (the app rotated it).
    let s2 = open(&net, &dir, &Keys::generate());
    let _sig2 = sign_in_as(&net, &s2, &persona);
    let book = s2.played_with().unwrap();
    assert_eq!(book.len(), 1);
    assert_eq!(book.list()[0].name, "Alex");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn another_persona_cannot_sign_in_over_a_signed_in_one() {
    let net = FakeNetwork::new();
    let dir = temp_dir("h1-switch");
    let s = open(&net, &dir, &Keys::generate());
    let a = Keys::generate();
    let _sa = sign_in_as(&net, &s, &a);
    // The key already carries a persona, so a second sign-in on it is
    // refused before any pairing starts (the key must be replaced first).
    assert!(s.runtime_key_used());
    assert_eq!(
        s.sign_in_refusal(),
        Some(decented_signet::SignInRefusal::KeyAlreadyUsed)
    );
    let si = s.sign_in();
    assert!(
        matches!(drain_sign_in(&si, T).last(), Some(SignInEvent::Failed { reason }) if reason == decented_signet::RUNTIME_KEY_USED)
    );
    assert_eq!(s.persona(), Some(a.public_key()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_grant_not_bound_to_the_signed_in_persona_is_dropped() {
    let net = FakeNetwork::new();
    let dir = temp_dir("h1-legacy");
    let (s, _signer) = signed_in(&net, &dir, &Keys::generate());
    give_contacts(&net, &s, json!([]));
    // An older file has no persona binding.
    let path = dir.join("signet/contacts-grant.json");
    let mut g: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(g.as_object_mut().unwrap().remove("persona").is_some());
    std::fs::write(&path, g.to_string()).unwrap();
    let again = open(&net, &dir, &Keys::generate());
    assert!(again.is_signed_in());
    assert!(!again.has_contacts_grant());
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(dir);
}

// ─── M1: pairing ────────────────────────────────────────────────────────────

/// A raced ack and My Signet's own ack conflict, so the pairing fails and
/// Continue stores nothing.
#[test]
fn raced_pairing_ack_fails_closed() {
    let net = FakeNetwork::new();
    let kid_p = Keys::generate();
    let (kid, _sk) = signed_in(&net, &temp_dir("m1-kid"), &kid_p);

    let p = kid.pair_contacts().unwrap();
    wait_for(T, "awaiting", || p.poll());
    let attacker = FakeRail::approve(&net, &p.links().web, RELAY); // raced ack
    let _real = FakeRail::approve(&net, &p.links().web, RELAY); // My Signet's ack
    let reason = wait_for(T, "conflict", || match p.poll() {
        Some(PairingEvent::Failed { reason }) => Some(reason),
        Some(PairingEvent::VerificationCode { .. }) | None => None,
        Some(e) => panic!("{e:?}"),
    });
    assert!(reason.contains("Two different answers"), "{reason}");
    attacker.publish(
        json!([contact(
            'e',
            &Keys::generate().public_key(),
            "Mum",
            "kin",
            false
        )]),
        now(),
        false,
    );
    p.confirm(); // pressed anyway
    std::thread::sleep(QUIET);
    assert!(p.poll().is_none());
    assert!(!kid.has_contacts_grant());
}

#[test]
fn a_late_conflicting_ack_while_the_code_is_shown_fails_the_pairing() {
    let net = FakeNetwork::new();
    let (s, _signer) = signed_in(&net, &temp_dir("m1-late"), &Keys::generate());
    let p = s.pair_contacts().unwrap();
    wait_for(T, "awaiting", || p.poll());
    let real = FakeRail::approve(&net, &p.links().web, RELAY);
    let PairingEvent::VerificationCode { code } = wait_for(T, "code", || p.poll()) else {
        panic!()
    };
    assert_eq!(code, real.expected_code());
    // The same answer again (a stored copy) is fine; a different one is not.
    let _other = FakeRail::approve(&net, &p.links().web, RELAY);
    assert!(matches!(
        wait_for(T, "failed", || p.poll()),
        PairingEvent::Failed { .. }
    ));
    p.confirm();
    std::thread::sleep(QUIET);
    assert!(!s.has_contacts_grant());
}

#[test]
fn my_signet_cancelling_the_grant_after_continue_fails_the_pairing() {
    let net = FakeNetwork::new();
    let (s, _signer) = signed_in(&net, &temp_dir("m1-revoked"), &Keys::generate());
    let p = s.pair_contacts().unwrap();
    wait_for(T, "awaiting", || p.poll());
    let rail = FakeRail::approve(&net, &p.links().web, RELAY);
    wait_for(T, "code", || p.poll());
    rail.publish(json!([]), now(), true); // the typed code did not match
    p.confirm();
    assert!(matches!(
        wait_for(T, "failed", || p.poll()),
        PairingEvent::Failed { .. }
    ));
    assert!(!s.has_contacts_grant());
}

#[test]
fn dropping_a_pairing_before_continue_cancels_it() {
    let net = FakeNetwork::new();
    let dir = temp_dir("m1-drop");
    let (s, _signer) = signed_in(&net, &dir, &Keys::generate());
    let p = s.pair_contacts().unwrap();
    wait_for(T, "awaiting", || p.poll());
    let web = p.links().web.clone();
    drop(p);
    std::thread::sleep(Duration::from_millis(50));
    let _rail = FakeRail::approve(&net, &web, RELAY);
    std::thread::sleep(QUIET);
    assert!(!s.has_contacts_grant());
    let _ = std::fs::remove_dir_all(dir);
}

// ─── Blocks ─────────────────────────────────────────────────────────────────

#[test]
fn an_open_inbox_refreshes_contacts_by_itself() {
    let net = FakeNetwork::new();
    let alex = player(&net, "m4-alex2");
    let bea_p = Keys::generate();
    let dir = temp_dir("m4-bea2");
    let mut cfg: SignetConfig = config(&dir);
    cfg.contacts_refresh = Duration::from_secs(1);
    let bea_rt = Keys::generate();
    let bea = Signet::with_connector(cfg, bea_rt.clone(), Arc::new(net.clone()));
    let sb = sign_in_as(&net, &bea, &bea_p);
    let rail = give_contacts(
        &net,
        &bea,
        json!([contact(
            'a',
            &alex.persona.public_key(),
            "Alex",
            "kin",
            false
        )]),
    );
    let bea = Player {
        s: bea,
        persona: bea_p,
        runtime: bea_rt,
        signer: sb,
        dir,
    };
    meet(&bea, &alex, "Alex");
    meet(&alex, &bea, "Bea");
    let inbox = bea.s.inbox();
    rail.publish(
        json!([contact(
            'a',
            &alex.persona.public_key(),
            "Alex",
            "kin",
            true
        )]),
        now() + 1,
        false,
    );
    wait_for(T, "background refresh", || {
        bea.s
            .contact_book()
            .filter(|b| b.is_blocked(&alex.persona.public_key()))
    });
    send(&alex, &bea);
    std::thread::sleep(QUIET);
    assert!(inbox.poll().is_none());
}

/// Blocks survive the grant going away.
#[test]
fn blocks_outlive_a_revoked_grant() {
    let net = FakeNetwork::new();
    let alex = player(&net, "l5-alex");
    let bea_p = Keys::generate();
    let bea_rt = Keys::generate();
    let dir = temp_dir("l5-bea");
    let bea = open(&net, &dir, &bea_rt);
    let sb = sign_in_as(&net, &bea, &bea_p);
    let rail = give_contacts(
        &net,
        &bea,
        json!([contact(
            'a',
            &alex.persona.public_key(),
            "Alex",
            "kin",
            true
        )]),
    );
    let bea = Player {
        s: bea,
        persona: bea_p,
        runtime: bea_rt,
        signer: sb,
        dir: dir.clone(),
    };
    meet(&bea, &alex, "Alex");
    meet(&alex, &bea, "Bea");
    rail.publish(json!([]), now() + 1, true);
    assert_eq!(
        bea.s.refresh_contacts().wait(T).unwrap(),
        Ok(ContactsSync::Revoked)
    );
    assert!(
        dir.join("signet/kept-blocks.json").exists(),
        "kept across restarts"
    );
    let inbox = bea.s.inbox();
    send(&alex, &bea);
    std::thread::sleep(QUIET);
    assert!(inbox.poll().is_none(), "still blocked");
}

/// A played-with person's self-chosen host name is not what the UI shows.
#[test]
fn the_host_name_in_the_payload_is_not_shown_as_the_sender() {
    let net = FakeNetwork::new();
    let (alex, bea) = {
        let (x, y) = (player(&net, "l4-alex"), player(&net, "l4-bea"));
        meet(&x, &y, "Bea");
        // Bea has Alex with no name at all.
        meet(&y, &x, "");
        (x, y)
    };
    let inbox = bea.s.inbox();
    send(&alex, &bea);
    let inv = wait_for(T, "invite", || inbox.poll());
    assert_eq!(inv.payload.host_name, "Mum");
    assert!(
        inv.display_sender().starts_with("npub1"),
        "{}",
        inv.display_sender()
    );
}

/// A sign-in dialog dropped before approval persists nothing.
#[test]
fn dropping_a_sign_in_before_approval_cancels_it() {
    let net = FakeNetwork::new();
    let dir = temp_dir("l1-drop");
    let s = open(&net, &dir, &Keys::generate());
    let signer = FakeMySignet::new(&net, Keys::generate());
    let si = s.sign_in();
    wait_for(T, "listening", || {
        si.poll().filter(|e| *e == SignInEvent::AwaitingApproval)
    });
    let uri = si.nostrconnect_uri().to_string();
    drop(si);
    std::thread::sleep(Duration::from_millis(50));
    signer.handle_nostrconnect(&uri);
    std::thread::sleep(QUIET);
    assert!(!s.is_signed_in());
    assert!(!dir.join("signet/session.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

// ─── SG16: a debug print of a session keeps the client secret out ───────────

#[test]
fn a_debug_print_of_a_session_does_not_show_the_client_secret() {
    let secret = "7f".repeat(32);
    let session = decented_signet::nip46::PersistedSession {
        app_secret_key: secret.clone(),
        remote_signer: "ab".repeat(32),
        relays: vec!["wss://relay.test".into()],
        persona: "cd".repeat(32),
    };
    let shown = format!("{session:?}");
    assert!(!shown.contains(&secret), "{shown}");
    assert!(shown.contains(&"ab".repeat(32)) && shown.contains("wss://relay.test"), "{shown}");
}

// ─── SG3: blocks that cannot be read are not thrown away ────────────────────

#[test]
fn damaged_kept_blocks_stay_on_disk() {
    let net = FakeNetwork::new();
    let dir = temp_dir("sg3-kept");
    let runtime = Keys::generate();
    {
        let s = open(&net, &dir, &runtime);
        sign_in_as(&net, &s, &Keys::generate());
    }
    let kept = dir.join("signet/kept-blocks.json");
    std::fs::write(&kept, b"{torn").unwrap();
    let s = open(&net, &dir, &runtime);
    assert!(s.is_signed_in());
    assert_eq!(std::fs::read(&kept).unwrap(), b"{torn", "left in place");
    drop(s);
    let _ = std::fs::remove_dir_all(dir);
}

// ─── SG7: sign-out takes the side copies of secret-bearing files too ────────

#[test]
fn sign_out_removes_aside_copies_and_leftover_temp_files() {
    let net = FakeNetwork::new();
    let dir = temp_dir("sg7-sides");
    let (s, _signer) = signed_in(&net, &dir, &Keys::generate());
    let sd = signet_dir(&dir);
    let sides = [
        "session.json.corrupt-1",
        "session.json.tmp",
        "signin.json.bad",
        "contacts-grant.json.corrupt-2",
        "contacts-grant.json.tmp",
        "contacts.json.bad-2",
        "kept-blocks.json.corrupt-3",
        "public-profile-session.json.corrupt-4",
        "public-note-session.json.tmp",
        "public-score-session.json.bad",
        "friend-links.json.corrupt-5",
        "friend-links.json.tmp",
        "profile.json.corrupt-6",
        "attestation.json.tmp",
    ];
    for f in sides {
        std::fs::write(sd.join(f), b"{\"app_secret_key\":\"7f\"}").unwrap();
    }
    s.sign_out().wait(T).unwrap();
    for f in sides {
        assert!(!sd.join(f).exists(), "{f} outlived the sign-out");
    }
    assert!(sd.join("runtime-keys.json").exists(), "the retired key is remembered");
    let _ = std::fs::remove_dir_all(dir);
}
