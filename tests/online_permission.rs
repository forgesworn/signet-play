//! "Ask My Signet to play online" (`?action=app-permission`,
//! `permission=online-play`) end to end over the in-memory relay network,
//! against a fake My Signet that answers the way `app-permission.ts` builds
//! its answers: a stored gift wrap to the session key, the rumor (kind 29999)
//! sealed by its author.

mod support;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use decented_signet::permission::{ALL_RELAYS_FAILED, NOT_SIGNED_IN, SIGNED_OUT_WHILE_WAITING};
use decented_signet::relay::FakeNetwork;
use decented_signet::{PermissionAsk, PermissionEvent, SignInEvent, Signet, SignetConfig};
use nostr::nips::nip44;
use nostr::util::JsonUtil;
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp, Url};
use serde_json::{Value, json};
use support::*;

const T: Duration = Duration::from_secs(10);
const A: &str = "wss://a.test";
const B: &str = "wss://b.test";
const REASON: &str = "Twang Thang shows the other players in a game that it's really you.";

fn open_with(
    net: &FakeNetwork,
    dir: &std::path::Path,
    runtime: &Keys,
    tweak: impl FnOnce(&mut SignetConfig),
) -> Signet {
    let mut c = config(dir);
    c.permission_reason = Some(REASON.into());
    tweak(&mut c);
    Signet::with_connector(c, runtime.clone(), Arc::new(net.clone()))
}

fn q(url: &str, k: &str) -> String {
    Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| panic!("no {k} in {url}"))
}

/// Seal `rumor_content` by `author` and gift-wrap it to `to` on `relay`, as
/// My Signet does.
fn send_wrap(
    net: &FakeNetwork,
    relay: &str,
    to: &PublicKey,
    author: &Keys,
    tags: Vec<[String; 2]>,
    content: String,
) {
    let t = now();
    let rumor = EventBuilder::new(Kind::Custom(29999), content)
        .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
        .custom_created_at(Timestamp::from(t))
        .build(author.public_key());
    let sealed =
        nip44::encrypt(author.secret_key(), to, rumor.as_json(), nip44::Version::V2).unwrap();
    let seal = EventBuilder::new(Kind::Seal, sealed)
        .custom_created_at(Timestamp::from(t - 9))
        .sign_with_keys(author)
        .unwrap();
    let eph = Keys::generate();
    let wrapped = nip44::encrypt(eph.secret_key(), to, seal.as_json(), nip44::Version::V2).unwrap();
    let wrap = EventBuilder::new(Kind::GiftWrap, wrapped)
        .tag(Tag::public_key(*to))
        .custom_created_at(Timestamp::from(t - 5))
        .sign_with_keys(&eph)
        .unwrap();
    net.hub(relay).publish(&wrap);
}

/// A direct-child persona signs in by Sign in with Signet with no bunker.
fn sign_in_no_bunker(net: &FakeNetwork, s: &Signet, persona: &Keys) {
    let si = s.sign_in_with_signet();
    assert_eq!(
        wait_for(T, "listening", || si.poll()),
        SignInEvent::AwaitingApproval
    );
    let link = si.app_link().to_string();
    let challenge = q(&link, "challenge");
    let auth: Event = EventBuilder::new(Kind::Custom(21236), "")
        .tags([
            Tag::parse(["challenge".to_string(), challenge.clone()]).unwrap(),
            Tag::parse(["origin".to_string(), q(&link, "origin")]).unwrap(),
        ])
        .sign_with_keys(persona)
        .unwrap();
    let body = json!({"type": "signet-auth-response", "requestId": challenge, "authEvent": auth, "displayName": "Kid"});
    let session = PublicKey::from_hex(&q(&link, "sessionPubkey")).unwrap();
    send_wrap(
        net,
        &q(&link, "relay"),
        &session,
        persona,
        vec![
            ["session".into(), challenge],
            ["status".into(), "approved".into()],
        ],
        body.to_string(),
    );
    let events = drain_sign_in(&si, T);
    assert!(
        matches!(events.last(), Some(SignInEvent::NoBunker { .. })),
        "{events:?}"
    );
    assert!(s.attestation().is_none());
}

/// What the app's link asks My Signet to sign.
fn template_of(link: &str) -> Value {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(q(link, "template"))
        .unwrap();
    serde_json::from_slice(&raw).unwrap()
}

/// My Signet on Allow: the template signed by the persona, the answer sealed
/// by the persona, on the relay the link names.
fn approve(net: &FakeNetwork, link: &str, persona: &Keys) {
    let t = template_of(link);
    let tags: Vec<Vec<String>> = serde_json::from_value(t["tags"].clone()).unwrap();
    let event = EventBuilder::new(Kind::Custom(30420), "")
        .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
        .sign_with_keys(persona)
        .unwrap();
    let challenge = q(link, "challenge");
    let content = json!({"type": "signet-app-permission-response", "permission": "online-play", "challenge": challenge, "event": event});
    send_wrap(
        net,
        &q(link, "relay"),
        &PublicKey::from_hex(&q(link, "sessionPubkey")).unwrap(),
        persona,
        vec![
            ["session".into(), challenge],
            ["status".into(), "approved".into()],
        ],
        content.to_string(),
    );
}

/// My Signet on Deny / Cancel: a throwaway key, `denied: true`.
fn deny(net: &FakeNetwork, link: &str) {
    let challenge = q(link, "challenge");
    let content = json!({"type": "signet-app-permission-response", "permission": "online-play", "challenge": challenge, "denied": true});
    send_wrap(
        net,
        &q(link, "relay"),
        &PublicKey::from_hex(&q(link, "sessionPubkey")).unwrap(),
        &Keys::generate(),
        vec![
            ["session".into(), challenge],
            ["status".into(), "rejected".into()],
        ],
        content.to_string(),
    );
}

fn waiting(ask: &PermissionAsk) {
    assert_eq!(
        wait_for(T, "waiting", || ask.poll()),
        PermissionEvent::Waiting
    );
    assert!(!ask.app_link().is_empty());
}

fn last(ask: &PermissionAsk) -> PermissionEvent {
    wait_for(T, "an end", || {
        ask.poll().filter(|e| *e != PermissionEvent::Waiting)
    })
}

#[test]
fn an_approval_is_stored_as_the_attestation_and_works_after_a_restart() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let runtime = Keys::generate();
    let dir = temp_dir("perm-ok");
    let s = open_with(&net, &dir, &runtime, |_| {});
    sign_in_no_bunker(&net, &s, &persona);

    let ask = s.ask_online_permission();
    assert_eq!(ask.app_link(), "", "no link before a relay listens");
    waiting(&ask);
    let link = ask.app_link().to_string();
    assert!(link.starts_with("https://mysignet.app/?action=app-permission&permission=online-play&origin=https%3A%2F%2Fdecented.org&name=Twang+Thang&reason="));
    assert_eq!(q(&link, "reason"), REASON);
    assert_eq!(q(&link, "callback"), "https://decented.org/signet");
    assert_eq!(q(&link, "relay"), RELAY);
    assert_eq!(ask.relay_host(), "relay.test");
    let t = template_of(&link);
    assert_eq!(t["pubkey"], json!(persona.public_key().to_hex()));
    assert_eq!(t["tags"][0], json!(["d", APP_ID]));
    assert_eq!(t["tags"][1], json!(["p", runtime.public_key().to_hex()]));
    assert!(t.get("created_at").is_none());

    approve(&net, &link, &persona);
    let PermissionEvent::Approved(info) = last(&ask) else {
        panic!("not approved")
    };
    assert_eq!(info.persona, persona.public_key());
    assert_eq!(info.runtime, runtime.public_key());
    assert_eq!(s.attestation(), Some(info.clone()));
    assert!(s.attestation_json().is_some() && s.attestation_event().is_some());
    assert!(!s.has_signer(), "still no bunker");
    assert!(!s.permission_renewal_due(now()));
    assert!(s.permission_renewal_due(info.valid_until - 6 * 86_400));
    assert!(
        !s.permission_renewal_due(info.valid_until + 1),
        "expired is not 'renewal due'"
    );
    // Nothing went public: no 30420 on the relay.
    assert!(
        net.hub(RELAY)
            .published()
            .iter()
            .all(|e| e.kind != Kind::Custom(30420))
    );
    // The answer was awaited on a connection that carried nothing else.
    let reqs = net.hub(RELAY).reqs();
    // (The ask's is the last gift-wrap subscription: the sign-in's came first.)
    let conn = reqs
        .iter()
        .rev()
        .find(|r| {
            r.filters.iter().any(|f| {
                f.kinds
                    .as_ref()
                    .is_some_and(|k| k.contains(&Kind::GiftWrap))
            })
        })
        .map(|r| r.connection)
        .expect("subscribed for the answer");
    assert_eq!(reqs.iter().filter(|r| r.connection == conn).count(), 1);

    // A restart keeps it, as for a bunker-signed attestation.
    drop(ask);
    let again = open_with(&net, &dir, &runtime, |_| {});
    assert_eq!(again.attestation(), Some(info));
    assert!(again.attestation_json().is_some());
    // Sign-out forgets it.
    again.sign_out().wait(T).unwrap();
    assert!(again.attestation().is_none());
    assert!(!signet_dir(&dir).join("attestation.json").exists());
}

#[test]
fn a_denial_ends_the_ask_and_keeps_nothing() {
    let net = FakeNetwork::new();
    let s = open_with(&net, &temp_dir("perm-deny"), &Keys::generate(), |_| {});
    sign_in_no_bunker(&net, &s, &Keys::generate());
    let ask = s.ask_online_permission();
    waiting(&ask);
    deny(&net, ask.app_link());
    assert_eq!(last(&ask), PermissionEvent::Denied);
    assert!(s.attestation().is_none());
}

#[test]
fn a_bad_answer_is_dropped_and_the_ask_keeps_waiting() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("perm-bad"), &Keys::generate(), |_| {});
    sign_in_no_bunker(&net, &s, &persona);
    let ask = s.ask_online_permission();
    waiting(&ask);
    // Signed by another key: not the template's persona.
    approve(&net, ask.app_link(), &Keys::generate());
    std::thread::sleep(Duration::from_millis(150));
    assert!(ask.poll().is_none());
    approve(&net, ask.app_link(), &persona);
    assert!(matches!(last(&ask), PermissionEvent::Approved(_)));
}

#[test]
fn no_answer_times_out() {
    let net = FakeNetwork::new();
    let s = open_with(&net, &temp_dir("perm-timeout"), &Keys::generate(), |c| {
        c.permission_wait = Duration::from_millis(400)
    });
    sign_in_no_bunker(&net, &s, &Keys::generate());
    let ask = s.ask_online_permission();
    waiting(&ask);
    assert_eq!(last(&ask), PermissionEvent::TimedOut);
    // Asking again is a fresh request.
    let again = s.ask_online_permission();
    waiting(&again);
    assert_ne!(
        q(ask.app_link(), "challenge"),
        q(again.app_link(), "challenge")
    );
    assert_ne!(
        q(ask.app_link(), "sessionPubkey"),
        q(again.app_link(), "sessionPubkey")
    );
}

#[test]
fn an_answer_after_a_sign_out_is_dropped() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let dir = temp_dir("perm-signout");
    let s = open_with(&net, &dir, &Keys::generate(), |_| {});
    sign_in_no_bunker(&net, &s, &persona);
    let ask = s.ask_online_permission();
    waiting(&ask);
    s.sign_out().wait(T).unwrap();
    approve(&net, ask.app_link(), &persona);
    assert_eq!(
        last(&ask),
        PermissionEvent::Failed {
            reason: SIGNED_OUT_WHILE_WAITING.into()
        }
    );
    assert!(s.attestation().is_none());
    assert!(!signet_dir(&dir).join("attestation.json").exists());
}

#[test]
fn a_newer_ask_replaces_an_older_one() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("perm-newer"), &Keys::generate(), |_| {});
    sign_in_no_bunker(&net, &s, &persona);
    let old = s.ask_online_permission();
    waiting(&old);
    let new = s.ask_online_permission();
    waiting(&new);
    approve(&net, old.app_link(), &persona);
    assert!(matches!(last(&old), PermissionEvent::Failed { .. }));
    assert!(s.attestation().is_none());
}

#[test]
fn a_fresh_link_for_the_remaining_wait_replaces_the_old_ask_and_keeps_the_clock() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("perm-renew"), &Keys::generate(), |_| {});
    sign_in_no_bunker(&net, &s, &persona);
    assert_eq!(s.permission_wait(), Duration::from_secs(660));
    let old = s.ask_online_permission();
    waiting(&old);
    // A fresh link that waits only what is left (here: 400 ms).
    let new = s.ask_online_permission_within(Duration::from_millis(400));
    waiting(&new);
    assert_ne!(q(old.app_link(), "challenge"), q(new.app_link(), "challenge"));
    // Only the newest ask's answer counts.
    approve(&net, old.app_link(), &persona);
    assert!(matches!(last(&old), PermissionEvent::Failed { .. }));
    assert!(s.attestation().is_none());
    // The new one ends at the shorter wait.
    assert_eq!(last(&new), PermissionEvent::TimedOut);
}

#[test]
fn the_ask_says_when_it_is_listening_and_can_be_told_to_reconnect() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("perm-reconnect"), &Keys::generate(), |_| {});
    sign_in_no_bunker(&net, &s, &persona);
    let ask = s.ask_online_permission();
    assert!(!ask.listening(), "nothing listens before a relay opens");
    ask.reconnect(); // a no-op, not a panic
    waiting(&ask);
    assert!(ask.listening());
    ask.reconnect(); // the in-memory relay has nothing to redial
    approve(&net, ask.app_link(), &persona);
    assert!(matches!(last(&ask), PermissionEvent::Approved(_)));
}

#[test]
fn the_first_relay_down_means_the_next_is_used_and_named() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    net.hub(A)
        .set_failing("HTTP error: 503 Service Unavailable");
    let s = open_with(&net, &temp_dir("perm-skip"), &Keys::generate(), |c| {
        c.signin_relays = vec![A.into(), B.into()];
    });
    sign_in_no_bunker(&net, &s, &persona);
    let ask = s.ask_online_permission();
    waiting(&ask);
    assert_eq!(q(ask.app_link(), "relay"), B);
    assert_eq!(ask.relay_host(), "b.test");
    approve(&net, ask.app_link(), &persona);
    assert!(matches!(last(&ask), PermissionEvent::Approved(_)));
}

#[test]
fn when_no_relay_opens_each_one_is_named() {
    let net = FakeNetwork::new();
    let s = open_with(&net, &temp_dir("perm-allfail"), &Keys::generate(), |c| {
        c.signin_relays = vec![A.into()];
    });
    sign_in_no_bunker(&net, &s, &Keys::generate());
    net.hub(A).set_offline(true);
    net.hub(RELAY)
        .set_failing("HTTP error: 503 Service Unavailable");
    let ask = s.ask_online_permission();
    let PermissionEvent::Failed { reason } = last(&ask) else {
        panic!("expected Failed")
    };
    assert_eq!(
        reason,
        format!("{ALL_RELAYS_FAILED}\na.test: couldn't connect · relay.test: unavailable (503)")
    );
    assert_eq!(ask.app_link(), "");
}

#[test]
fn refused_when_signed_out_or_not_set_up() {
    let net = FakeNetwork::new();
    let s = open_with(&net, &temp_dir("perm-out"), &Keys::generate(), |_| {});
    assert_eq!(
        last(&s.ask_online_permission()),
        PermissionEvent::Failed {
            reason: NOT_SIGNED_IN.into()
        }
    );
    let s = open_with(&net, &temp_dir("perm-noreason"), &Keys::generate(), |c| {
        c.permission_reason = None
    });
    sign_in_no_bunker(&net, &s, &Keys::generate());
    assert!(matches!(
        last(&s.ask_online_permission()),
        PermissionEvent::Failed { .. }
    ));
    let s = open_with(&net, &temp_dir("perm-norelay"), &Keys::generate(), |c| {
        c.permission_reason = Some(REASON.into());
    });
    sign_in_no_bunker(&net, &s, &Keys::generate());
    s.sign_out().wait(T).unwrap();
    assert!(matches!(
        last(&s.ask_online_permission()),
        PermissionEvent::Failed { .. }
    ));
}

/// A persona with a bunker may ask too (an adult on their own persona).
#[test]
fn a_persona_with_a_signer_may_ask_too() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("perm-bunker"), &Keys::generate(), |_| {});
    let _signer = sign_in_as(&net, &s, &persona);
    let ask = s.ask_online_permission();
    waiting(&ask);
    approve(&net, ask.app_link(), &persona);
    assert!(matches!(last(&ask), PermissionEvent::Approved(_)));
    assert!(!s.permission_renewal_due(now()), "never with a signer");
}

/// A persona approved with no bunker is attestable: it receives friend
/// replies (the inbox) and uses friend links, with no NIP-46 session. Before
/// the approval the same calls refuse.
#[test]
fn an_approved_persona_with_no_bunker_uses_friend_links_and_the_inbox() {
    let net = FakeNetwork::new();
    let b = player(&net, "perm-fl-b");
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("perm-fl-a"), &Keys::generate(), |_| {});
    sign_in_no_bunker(&net, &s, &persona);
    let blink = b.s.create_friend_link().unwrap();

    // Not yet: no attestation, no bunker.
    assert!(!s.accepting_invites());
    assert!(s.create_friend_link().is_err());
    assert!(s.use_friend_link(&blink).wait(T).unwrap().is_err());

    let ask = s.ask_online_permission();
    waiting(&ask);
    approve(&net, ask.app_link(), &persona);
    assert!(matches!(last(&ask), PermissionEvent::Approved(_)));
    assert!(!s.has_signer() && s.accepting_invites());

    // Both friend-link directions work, and the inbox hears the reply.
    let inbox = s.inbox();
    s.use_friend_link(&blink).wait(T).unwrap().unwrap();
    let hello = wait_for(T, "hello", || b.s.friend_hellos().into_iter().next());
    assert_eq!(hello.persona, persona.public_key());
    b.s.accept_hello(&hello.id).wait(T).unwrap().unwrap();
    let ev = wait_for(T, "added", || s.take_friend_events().into_iter().next());
    match ev {
        decented_signet::FriendEvent::Added { persona: p, .. } => {
            assert_eq!(p, b.persona.public_key())
        }
    }
    assert!(inbox.poll().is_none(), "a friend reply is not an invite");
    let mine = s.create_friend_link().unwrap();
    assert_eq!(mine.to, s.runtime_pubkey());
    // Contacts still need the bunker.
    assert!(s.pair_contacts().is_err());
}

/// A player relay that cannot carry the request (over 1024 characters) is
/// skipped, not fatal.
#[test]
fn an_unusable_player_relay_is_skipped() {
    let long = format!("wss://long.test/{}", "x".repeat(1100));
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("perm-skip"), &Keys::generate(), move |c| {
        c.signin_relays = vec![long.clone()];
        c.relays = vec![long, RELAY.to_string()];
    });
    sign_in_no_bunker(&net, &s, &persona);
    let ask = s.ask_online_permission();
    waiting(&ask);
    assert_eq!(q(ask.app_link(), "relay"), RELAY);
    approve(&net, ask.app_link(), &persona);
    assert!(matches!(last(&ask), PermissionEvent::Approved(_)));
}

/// The approval is the only thing that makes a no-bunker persona accept
/// invites: it stops at expiry, and a sign-out ends it for good.
#[test]
fn an_approved_persona_stops_accepting_invites_at_expiry_and_on_sign_out() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("perm-accept"), &Keys::generate(), |_| {});
    sign_in_no_bunker(&net, &s, &persona);
    assert!(!s.accepting_invites(), "nothing approved yet");
    let ask = s.ask_online_permission();
    waiting(&ask);
    approve(&net, ask.app_link(), &persona);
    let PermissionEvent::Approved(info) = last(&ask) else {
        panic!("not approved")
    };
    assert!(s.accepting_invites() && s.accepting_invites_at(info.valid_until));
    assert!(
        !s.accepting_invites_at(info.valid_until + 1),
        "an expired approval accepts nothing"
    );
    s.sign_out().wait(T).unwrap();
    assert!(!s.accepting_invites() && !s.accepting_invites_at(now()));
    let inbox = s.inbox();
    std::thread::sleep(Duration::from_millis(200));
    assert!(inbox.poll().is_none());
}
