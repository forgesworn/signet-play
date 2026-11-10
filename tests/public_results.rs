mod support;
use decented_signet::relay::FakeNetwork;
use decented_signet::sharing::{SharingApprovalEvent, SharingScope};
use nostr::{EventBuilder, Keys, Kind};
use serde_json::json;
use std::time::Duration;
use support::*;
const T: Duration = Duration::from_secs(10);

#[test]
fn cancelling_status_pairing_closes_the_request_and_ignores_a_late_approval() {
    let net = FakeNetwork::new();
    let s = open(&net, &temp_dir("cancel-profile-check"), &Keys::generate());
    let signer = sign_in_as(&net, &s, &Keys::generate());
    *signer.public_profile.lock().unwrap() = Some(true);
    let baseline = net.hub(RELAY).open_subscriptions();
    let pending = s.approve_result_sharing(SharingScope::Profile);
    let SharingApprovalEvent::OpenSigner(uri) = wait_for(T, "ready", || pending.poll()) else {
        panic!("not ready")
    };
    assert!(net.hub(RELAY).open_subscriptions() > baseline);
    drop(pending);
    wait_for(T, "cancel closes pairing subscription", || {
        (net.hub(RELAY).open_subscriptions() == baseline).then_some(())
    });
    signer.handle_nostrconnect(&uri);
    assert!(!s.has_public_profile_connection());
    assert!(s.public_profile_status().wait(T).unwrap().is_err());
    approve(&s, &signer, SharingScope::Profile).unwrap();
    assert!(
        s.has_public_profile_connection(),
        "a fresh retry still works"
    );
}

#[test]
fn unanswered_profile_pairing_explains_how_to_recover() {
    let net = FakeNetwork::new();
    let mut cfg = config(&temp_dir("unanswered-profile-check"));
    cfg.pairing_timeout = Duration::from_millis(100);
    let s = decented_signet::Signet::with_connector(
        cfg,
        Keys::generate(),
        std::sync::Arc::new(net.clone()),
    );
    let _signer = sign_in_as(&net, &s, &Keys::generate());
    let pending = s.approve_result_sharing(SharingScope::Profile);
    assert!(matches!(
        wait_for(T, "ready", || pending.poll()),
        SharingApprovalEvent::OpenSigner(_)
    ));
    let SharingApprovalEvent::Failed(message) = wait_for(T, "timeout", || pending.poll()) else {
        panic!("unanswered pairing should time out")
    };
    assert!(message.contains("update My Signet"));
    assert!(!s.has_public_profile_connection());
}

fn approve(
    s: &decented_signet::Signet,
    signer: &FakeMySignet,
    scope: SharingScope,
) -> Result<(), String> {
    let pending = s.approve_result_sharing(scope);
    loop {
        match wait_for(T, "sharing approval", || pending.poll()) {
            SharingApprovalEvent::OpenSigner(uri) => {
                let url = nostr::Url::parse(&uri).unwrap();
                let perms = url
                    .query_pairs()
                    .find(|(k, _)| k == "perms")
                    .unwrap()
                    .1
                    .into_owned();
                assert!(
                    !perms.contains("30420") && !perms.contains("sign_event:5"),
                    "sharing is a separate grant"
                );
                assert!(perms.split(',').any(|p| p == scope.permission()));
                signer.handle_nostrconnect(&uri);
            }
            SharingApprovalEvent::Connected => {}
            SharingApprovalEvent::Approved(status) => {
                assert_eq!(status.persona_pubkey, s.persona().unwrap().to_hex());
                return Ok(());
            }
            SharingApprovalEvent::Failed(e) => return Err(e),
        }
    }
}

#[test]
fn only_explicitly_approved_public_personas_publish_and_retries_keep_the_event_id() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open(&net, &temp_dir("public-post"), &Keys::generate());
    let signer = sign_in_as(&net, &s, &persona);
    *signer.public_profile.lock().unwrap() = Some(true);
    let before_approval = signer.stats.lock().unwrap().connects;
    approve(&s, &signer, SharingScope::Profile).unwrap();
    assert!(s.public_profile_status().wait(T).unwrap().unwrap().enabled);
    assert_eq!(
        signer.stats.lock().unwrap().connects,
        before_approval,
        "approval and its first refresh reuse the paired signer without another connect"
    );
    let connects = signer.stats.lock().unwrap().connects;
    assert!(s.public_profile_status().wait(T).unwrap().unwrap().enabled);
    assert_eq!(
        signer.stats.lock().unwrap().connects,
        connects,
        "foreground status checks reuse the approved connection"
    );
    let note = EventBuilder::text_note("A public result").build(persona.public_key());
    assert!(
        s.publish_public_result(SharingScope::Note, note.clone(), None)
            .wait(T)
            .unwrap()
            .is_err(),
        "a read-only pairing grants no posting rights"
    );
    approve(&s, &signer, SharingScope::Note).unwrap();
    let first = s
        .publish_public_result(SharingScope::Note, note.clone(), None)
        .wait(T)
        .unwrap()
        .unwrap();
    let retry = s
        .publish_public_result(SharingScope::Note, note, None)
        .wait(T)
        .unwrap()
        .unwrap();
    assert_eq!(first.id, retry.id);
    assert_eq!(
        net.hub(RELAY)
            .query(&[nostr::Filter::new().kind(Kind::TextNote)])
            .len(),
        1
    );
    *signer.public_profile.lock().unwrap() = Some(false);
    assert!(
        s.publish_public_result(
            SharingScope::Note,
            EventBuilder::text_note("Private now").build(persona.public_key()),
            None
        )
        .wait(T)
        .unwrap()
        .is_err()
    );
    assert_eq!(
        signer
            .stats
            .lock()
            .unwrap()
            .signed_kinds
            .iter()
            .filter(|k| **k == 1)
            .count(),
        2,
        "private status prevents asking for another signature"
    );
    s.sign_out().wait(T).unwrap();
    assert!(!s.has_public_profile_connection() && !s.has_sharing_permission(SharingScope::Note));
}

#[test]
fn cached_metadata_and_forged_or_stale_status_never_allow_public_posting() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open(&net, &temp_dir("public-status-binding"), &Keys::generate());
    let signer = sign_in_as(&net, &s, &persona);
    assert!(
        approve(&s, &signer, SharingScope::Profile).is_err(),
        "old signer extension is unsupported"
    );
    *signer.public_profile.lock().unwrap() = Some(false);
    approve(&s, &signer, SharingScope::Profile).unwrap();
    assert!(!s.public_profile_status().wait(T).unwrap().unwrap().enabled);
    assert!(approve(&s, &signer, SharingScope::Note).is_err());
    *signer.public_profile.lock().unwrap() = Some(true);
    for patch in [
        json!({"v":2}),
        json!({"requestId":"replayed"}),
        json!({"clientPubkey":Keys::generate().public_key().to_hex()}),
        json!({"personaPubkey":Keys::generate().public_key().to_hex()}),
        json!({"checkedAt":1,"expiresAt":5001}),
        json!({"expiresAt":u64::MAX}),
    ] {
        *signer.status_patch.lock().unwrap() = patch;
        assert!(s.public_profile_status().wait(T).unwrap().is_err());
    }
    assert!(
        net.hub(RELAY)
            .published()
            .iter()
            .all(|e| e.kind != Kind::TextNote)
    );
}

#[test]
fn becoming_private_while_signing_or_a_substituted_signature_never_reaches_relays() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open(&net, &temp_dir("post-final-check"), &Keys::generate());
    let signer = sign_in_as(&net, &s, &persona);
    *signer.public_profile.lock().unwrap() = Some(true);
    approve(&s, &signer, SharingScope::Profile).unwrap();
    approve(&s, &signer, SharingScope::Note).unwrap();
    for mode in [
        SignMode::PrivatiseWhileSigning,
        SignMode::Substitute,
        SignMode::WrongKey,
    ] {
        *signer.public_profile.lock().unwrap() = Some(true);
        *signer.sign.lock().unwrap() = mode;
        let result = s
            .publish_public_result(
                SharingScope::Note,
                EventBuilder::text_note("Result").build(persona.public_key()),
                None,
            )
            .wait(T)
            .unwrap();
        assert!(result.is_err());
    }
    assert!(
        net.hub(RELAY)
            .published()
            .iter()
            .all(|e| e.kind != Kind::TextNote)
    );
}

#[test]
fn approval_for_a_different_persona_or_after_signout_cannot_be_installed() {
    let net = FakeNetwork::new();
    let s = open(&net, &temp_dir("sharing-persona-switch"), &Keys::generate());
    let _signed_in = sign_in_as(&net, &s, &Keys::generate());
    let other = FakeMySignet::new(&net, Keys::generate());
    *other.public_profile.lock().unwrap() = Some(true);
    assert!(approve(&s, &other, SharingScope::Profile).is_err());
    let pending = s.approve_result_sharing(SharingScope::Profile);
    let SharingApprovalEvent::OpenSigner(uri) = wait_for(T, "ready", || pending.poll()) else {
        panic!("not ready")
    };
    s.sign_out().wait(T).unwrap();
    other.handle_nostrconnect(&uri);
    assert!(matches!(
        wait_for(T, "refused old session", || pending.poll()),
        SharingApprovalEvent::Failed(_)
    ));
    assert!(!s.has_public_profile_connection());
}

#[test]
fn revoked_posting_permission_can_be_explicitly_approved_again_without_changing_game_identity() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open(&net, &temp_dir("posting-revoked"), &Keys::generate());
    let signer = sign_in_as(&net, &s, &persona);
    *signer.public_profile.lock().unwrap() = Some(true);
    approve(&s, &signer, SharingScope::Profile).unwrap();
    approve(&s, &signer, SharingScope::Note).unwrap();
    *signer.sign.lock().unwrap() = SignMode::PermissionRevoked;
    let event = EventBuilder::text_note("Result").build(persona.public_key());
    assert!(
        s.publish_public_result(SharingScope::Note, event.clone(), None)
            .wait(T)
            .unwrap()
            .is_err()
    );
    assert!(!s.has_sharing_permission(SharingScope::Note));
    assert!(s.has_public_profile_connection());
    assert_eq!(s.persona(), Some(persona.public_key()));
    *signer.sign.lock().unwrap() = SignMode::Approve;
    approve(&s, &signer, SharingScope::Note).unwrap();
    assert!(
        s.publish_public_result(SharingScope::Note, event, None)
            .wait(T)
            .unwrap()
            .is_ok()
    );
}

#[test]
fn gamestr_scores_require_their_own_public_conditional_scope() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open(&net, &temp_dir("score-scope"), &Keys::generate());
    let signer = sign_in_as(&net, &s, &persona);
    *signer.public_profile.lock().unwrap() = Some(true);
    approve(&s, &signer, SharingScope::Profile).unwrap();
    approve(&s, &signer, SharingScope::Note).unwrap();
    let score = EventBuilder::new(Kind::Custom(30762), "Score")
        .tags([
            nostr::Tag::public_key(persona.public_key()),
            nostr::Tag::identifier("test-score"),
        ])
        .allow_self_tagging()
        .build(persona.public_key());
    assert!(
        s.publish_public_result(SharingScope::Score, score.clone(), None)
            .wait(T)
            .unwrap()
            .is_err()
    );
    approve(&s, &signer, SharingScope::Score).unwrap();
    let posted = s
        .publish_public_result(SharingScope::Score, score, None)
        .wait(T)
        .unwrap()
        .unwrap();
    assert_eq!(posted.kind, Kind::Custom(30762));
    assert!(
        posted
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["p", &persona.public_key().to_hex()])
    );
    assert!(
        !net.hub(RELAY)
            .published()
            .iter()
            .any(|e| e.kind == Kind::TextNote)
    );
}
