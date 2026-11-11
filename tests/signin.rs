//! Sign-in, resume, attestation and profile against a fake My Signet.

mod support;

use std::time::Duration;

use decented_signet::relay::FakeNetwork;
use decented_signet::{SignInEvent, verify_attestation};
use nostr::{Keys, Kind};
use support::*;

const T: Duration = Duration::from_secs(10);

#[test]
fn sign_in_happy_path_persists_and_attests_without_publishing() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let signer = FakeMySignet::new(&net, persona.clone());
    publish_profile(&net, &persona, r#"{"name":"alex","display_name":"Alex"}"#);
    let dir = temp_dir("happy");
    let runtime = Keys::generate();
    let s = open(&net, &dir, &runtime);
    assert!(!s.is_signed_in());

    let si = s.sign_in();
    assert!(si.nostrconnect_uri().starts_with("nostrconnect://"));
    assert!(si.nostrconnect_uri().contains("perms=sign_event%3A30420"));
    assert!(
        si.app_link()
            .starts_with("https://mysignet.app/?nostrconnect=nostrconnect%3A%2F%2F")
    );
    assert!(
        si.app_link()
            .ends_with("&callback=twangthang%3A%2F%2Fsignin")
    );
    signer.open_app_link(si.app_link());

    let events = drain_sign_in(&si, T);
    assert_eq!(events[0], SignInEvent::AwaitingApproval);
    assert_eq!(
        events[1],
        SignInEvent::Connected {
            persona: persona.public_key()
        }
    );
    assert_eq!(events[2], SignInEvent::AwaitingSignature);
    let SignInEvent::Attested { info } = &events[3] else {
        panic!("{events:?}")
    };
    assert_eq!(info.persona, persona.public_key());
    assert_eq!(info.runtime, runtime.public_key());

    assert!(s.is_signed_in());
    assert_eq!(s.persona(), Some(persona.public_key()));
    assert!(!s.needs_refresh(now()));
    // The transport's opaque slot verifies.
    let json = s.attestation_json().unwrap();
    assert!(json.len() <= 2048);
    assert_eq!(
        verify_attestation(APP_ID, &json, &runtime.public_key(), now())
            .unwrap()
            .persona,
        persona.public_key()
    );
    // The attestation is kept on the phone and published nowhere.
    assert!(
        net.hub(RELAY)
            .published()
            .iter()
            .all(|e| e.kind != Kind::Custom(30420))
    );
    assert!(
        net.hub(RELAY)
            .query(&[nostr::Filter::new().kind(Kind::Custom(30420))])
            .is_empty()
    );
    let stored: nostr::Event =
        serde_json::from_slice(&std::fs::read(dir.join("signet/attestation.json")).unwrap())
            .unwrap();
    assert_eq!(stored.kind, Kind::Custom(30420));
    // Profile name arrives in the background.
    wait_for(T, "profile", || {
        (s.display_name().as_deref() == Some("Alex")).then_some(())
    });
    assert_eq!(signer.stats().signed_kinds, vec![30420]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn explicit_refusal_fails_fast() {
    let net = FakeNetwork::new();
    let signer = FakeMySignet::new(&net, Keys::generate());
    *signer.pair.lock().unwrap() = PairMode::Refuse;
    let dir = temp_dir("refuse");
    let s = open(&net, &dir, &Keys::generate());
    let si = s.sign_in();
    signer.handle_nostrconnect(si.nostrconnect_uri());
    let events = drain_sign_in(&si, T);
    let SignInEvent::Failed { reason } = events.last().unwrap() else {
        panic!("{events:?}")
    };
    // The fake signer's refusal does not echo the secret, so the client drops
    // its text and reports the generic one.
    assert!(reason.contains("the pairing was refused"), "{reason}");
    assert!(!reason.contains("user denied"), "{reason}");
    assert!(!s.is_signed_in());
    assert!(!dir.join("signet/session.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn deny_without_reply_times_out_and_stores_nothing() {
    let net = FakeNetwork::new();
    let signer = FakeMySignet::new(&net, Keys::generate());
    *signer.pair.lock().unwrap() = PairMode::Ignore;
    let dir = temp_dir("ignore");
    let mut cfg = config(&dir);
    cfg.pairing_timeout = Duration::from_millis(300);
    let s = decented_signet::Signet::with_connector(
        cfg,
        Keys::generate(),
        std::sync::Arc::new(net.clone()),
    );
    let si = s.sign_in();
    signer.handle_nostrconnect(si.nostrconnect_uri());
    let events = drain_sign_in(&si, T);
    assert!(
        matches!(events.last(), Some(SignInEvent::Failed { .. })),
        "{events:?}"
    );
    assert!(!s.is_signed_in());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_ack_or_wrong_secret_from_an_impostor_does_not_pair() {
    let net = FakeNetwork::new();
    let dir = temp_dir("impostor");
    let mut cfg = config(&dir);
    cfg.pairing_timeout = Duration::from_millis(400);
    let s = decented_signet::Signet::with_connector(
        cfg,
        Keys::generate(),
        std::sync::Arc::new(net.clone()),
    );
    let si = s.sign_in();
    // The relay saw our #p subscription and races a reply without the secret.
    let impostor = FakeMySignet::new(&net, Keys::generate());
    let uri = si.nostrconnect_uri().to_string();
    let wrong = {
        let (head, tail) = uri.split_once("secret=").unwrap();
        format!(
            "{head}secret=ffffffffffffffffffffffffffffffff{}",
            &tail[32..]
        )
    };
    impostor.handle_nostrconnect(&wrong);
    let events = drain_sign_in(&si, T);
    assert!(
        matches!(events.last(), Some(SignInEvent::Failed { .. })),
        "{events:?}"
    );
    assert!(!s.is_signed_in());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn sign_denied_leaves_signed_in_without_attestation_then_refresh_works() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let signer = FakeMySignet::new(&net, persona.clone());
    *signer.sign.lock().unwrap() = SignMode::Deny;
    let dir = temp_dir("denysign");
    let s = open(&net, &dir, &Keys::generate());
    let si = s.sign_in();
    signer.handle_nostrconnect(si.nostrconnect_uri());
    let events = drain_sign_in(&si, T);
    let Some(SignInEvent::AttestationFailed { reason }) = events.last() else {
        panic!("{events:?}")
    };
    assert!(reason.contains("user denied"), "{reason}");
    assert!(s.is_signed_in());
    assert!(s.attestation().is_none());
    assert!(s.needs_refresh(now()));

    *signer.sign.lock().unwrap() = SignMode::Approve;
    let info = s.refresh_attestation().wait(T).unwrap().unwrap();
    assert_eq!(info.persona, persona.public_key());
    assert!(!s.needs_refresh(now()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn substituted_or_foreign_signatures_are_refused() {
    for mode in [SignMode::Substitute, SignMode::WrongKey] {
        let net = FakeNetwork::new();
        let signer = FakeMySignet::new(&net, Keys::generate());
        *signer.sign.lock().unwrap() = mode;
        let dir = temp_dir("subst");
        let s = open(&net, &dir, &Keys::generate());
        let si = s.sign_in();
        signer.handle_nostrconnect(si.nostrconnect_uri());
        let events = drain_sign_in(&si, T);
        assert!(
            matches!(events.last(), Some(SignInEvent::AttestationFailed { .. })),
            "{mode:?}: {events:?}"
        );
        assert!(s.attestation().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn resume_restores_offline_and_refreshes_without_re_pairing() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let signer = FakeMySignet::new(&net, persona.clone());
    let dir = temp_dir("resume");
    let runtime = Keys::generate();
    let first_info = {
        let s = open(&net, &dir, &runtime);
        let si = s.sign_in();
        signer.handle_nostrconnect(si.nostrconnect_uri());
        let events = drain_sign_in(&si, T);
        let Some(SignInEvent::Attested { info }) = events.last() else {
            panic!("{events:?}")
        };
        info.clone()
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("signet/session.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "session holds the NIP-46 client secret"
        );
    }
    let session = std::fs::read_to_string(dir.join("signet/session.json")).unwrap();
    assert!(
        !session.contains(&persona.secret_key().to_secret_hex()),
        "never the persona key"
    );

    // Next launch: everything is back with no relay traffic needed.
    let s = open(&net, &dir, &runtime);
    assert!(s.is_signed_in());
    assert_eq!(s.persona(), Some(persona.public_key()));
    assert_eq!(s.attestation(), Some(first_info));
    assert!(!s.needs_refresh(now()));
    let pairs_before = signer.stats().get_public_key;

    // A refresh goes over the restored session: `connect`, then one signature.
    std::thread::sleep(Duration::from_millis(1100)); // a new created_at
    let info = s.refresh_attestation().wait(T).unwrap().unwrap();
    assert_eq!(info.persona, persona.public_key());
    let st = signer.stats();
    assert_eq!(st.connects, 1);
    assert_eq!(st.get_public_key, pairs_before, "no second pairing");
    assert_eq!(st.signed_kinds, vec![30420, 30420]);

    // A different runtime key (identity file regenerated) drops the stale attestation.
    let s2 = open(&net, &dir, &Keys::generate());
    assert!(s2.is_signed_in());
    assert!(s2.attestation().is_none());
    assert!(s2.needs_refresh(now()));

    // Sign-out forgets the session.
    s2.sign_out();
    assert!(!s2.is_signed_in());
    assert!(open(&net, &dir, &runtime).persona().is_none());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn display_name_falls_back_to_short_npub() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let signer = FakeMySignet::new(&net, persona.clone());
    let dir = temp_dir("noname");
    let s = open(&net, &dir, &Keys::generate());
    assert_eq!(s.display_name(), None);
    let si = s.sign_in();
    signer.handle_nostrconnect(si.nostrconnect_uri());
    drain_sign_in(&si, T);
    assert_eq!(s.refresh_profile().wait(T).unwrap(), None);
    let name = s.display_name().unwrap();
    assert!(name.starts_with("npub1") && name.contains('…'), "{name}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn nothing_naming_the_game_or_the_persona_is_ever_published() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let signer = FakeMySignet::new(&net, persona.clone());
    let dir = temp_dir("nopublish");
    let runtime = Keys::generate();
    let s = open(&net, &dir, &runtime);
    let si = s.sign_in();
    signer.handle_nostrconnect(si.nostrconnect_uri());
    drain_sign_in(&si, T);
    s.refresh_attestation().wait(T).unwrap().unwrap();
    let _ = s.refresh_profile().wait(T);
    // Opening an inbox and signing out publish nothing either.
    drop(s.inbox());
    assert!(s.sign_out().wait(T).unwrap().rotate_runtime_key);
    // Every event any relay accepted is NIP-46 traffic (kind 24133) from this
    // test's fake My Signet and the client; none is a 30420, a 5 or a 1059.
    let all = net.hub(RELAY).published();
    assert!(!all.is_empty());
    for ev in &all {
        assert_eq!(
            ev.kind,
            Kind::NostrConnect,
            "unexpected publish: kind {}",
            ev.kind.as_u16()
        );
    }
    // And signing out asked My Signet for nothing more.
    assert_eq!(signer.stats().signed_kinds, vec![30420, 30420]);
    let _ = std::fs::remove_dir_all(dir);
}
