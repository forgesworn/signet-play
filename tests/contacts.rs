//! Contacts-v2 app grant against a fake My Signet rail.

mod support;

use std::time::Duration;

use decented_signet::relay::FakeNetwork;
use decented_signet::{ContactsSync, PairingEvent, Tier};
use nostr::Keys;
use serde_json::json;
use support::*;

const T: Duration = Duration::from_secs(10);
const OTHER_RELAY: &str = "wss://contacts.relay.test";

fn next_event(p: &decented_signet::ContactsPairing) -> PairingEvent {
    wait_for(T, "pairing event", || p.poll())
}

#[test]
fn pairing_shows_the_code_then_syncs_the_projection() {
    let net = FakeNetwork::new();
    let dir = temp_dir("pair");
    let s = open(&net, &dir, &Keys::generate());
    assert!(s.pair_contacts().is_err(), "the grant is bound to a signed-in persona");
    let _signer = sign_in_as(&net, &s, &Keys::generate());
    let p = s.pair_contacts().unwrap();
    assert_eq!(next_event(&p), PairingEvent::AwaitingApproval);
    assert!(p.links().uri.starts_with("signet-grant://pair?v=2&"));
    assert!(p.links().app_link.starts_with("https://mysignet.app/pair?v=2&"));

    // The person approves in My Signet; the projection lives on another relay.
    let rail = FakeRail::approve(&net, &p.links().web, OTHER_RELAY);
    let PairingEvent::VerificationCode { code } = next_event(&p) else { panic!() };
    assert_eq!(code, rail.expected_code(), "the code the person types into My Signet");
    assert!(!s.has_contacts_grant(), "nothing kept before Continue");

    let (alex, sam, bo, kenny, nobody) = (
        Keys::generate().public_key(),
        Keys::generate().public_key(),
        Keys::generate().public_key(),
        Keys::generate().public_key(),
        Keys::generate().public_key(),
    );
    rail.publish(
        json!([
            contact('a', &alex, "Alex", "kith", false),
            contact('b', &sam, "Sam", "kin", false),
            contact('c', &bo, "Bo", "kin", true),
            contact('d', &kenny, "Kenny", "ken", false),
            contact('e', &nobody, "Nobody", "none", false),
        ]),
        now(),
        false,
    );
    p.confirm();
    assert_eq!(next_event(&p), PairingEvent::Paired { sync: ContactsSync::Updated { contacts: 4 } });
    assert!(s.has_contacts_grant());

    let list = s.contacts();
    let names: Vec<&str> = list.iter().map(|c| c.display_name.as_str()).collect();
    assert_eq!(names, ["Sam", "Alex", "Kenny", "Nobody"], "Kin, Kith, Ken, untiered; blocked never shown");
    assert_eq!(list[0].tier, Some(Tier::Kin));
    assert_eq!(list[0].identities, vec![sam]);
    let book = s.contact_book().unwrap();
    assert!(book.is_blocked(&bo));

    // Cached: a fresh open has the list with no network.
    let again = open(&FakeNetwork::new(), &dir, &Keys::generate());
    assert_eq!(again.contacts().len(), 4);

    // Refresh: unchanged, then newer, then revoked.
    assert_eq!(s.refresh_contacts().wait(T).unwrap(), Ok(ContactsSync::Unchanged));
    rail.publish(json!([contact('a', &alex, "Alex", "kin", false)]), now() + 1, false);
    assert_eq!(s.refresh_contacts().wait(T).unwrap(), Ok(ContactsSync::Updated { contacts: 1 }));
    assert_eq!(s.contacts()[0].tier, Some(Tier::Kin));
    rail.publish(json!([]), now() + 2, true);
    assert_eq!(s.refresh_contacts().wait(T).unwrap(), Ok(ContactsSync::Revoked));
    assert!(!s.has_contacts_grant());
    assert!(s.contacts().is_empty());
    assert!(!dir.join("signet/contacts-grant.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn cancel_on_the_code_screen_keeps_nothing() {
    let net = FakeNetwork::new();
    let dir = temp_dir("paircancel");
    let s = open(&net, &dir, &Keys::generate());
    let _signer = sign_in_as(&net, &s, &Keys::generate());
    let p = s.pair_contacts().unwrap();
    next_event(&p);
    let _rail = FakeRail::approve(&net, &p.links().web, RELAY);
    assert!(matches!(next_event(&p), PairingEvent::VerificationCode { .. }));
    p.cancel();
    std::thread::sleep(Duration::from_millis(50));
    assert!(!s.has_contacts_grant());
    assert!(!dir.join("signet/contacts-grant.json").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_ack_for_another_challenge_or_with_extra_caps_is_ignored() {
    let net = FakeNetwork::new();
    let dir = temp_dir("pairbad");
    let mut cfg = config(&dir);
    cfg.ack_timeout = Duration::from_millis(400);
    let s = decented_signet::Signet::with_connector(cfg, Keys::generate(), std::sync::Arc::new(net.clone()));
    let _signer = sign_in_as(&net, &s, &Keys::generate());
    let p = s.pair_contacts().unwrap();
    next_event(&p);
    // Wrong challenge.
    let web = p.links().web.clone();
    let (head, tail) = web.split_once("challenge=").unwrap();
    let wrong = format!("{head}challenge={}{}", "0".repeat(32), &tail[32..]);
    let _ = FakeRail::approve(&net, &wrong, RELAY);
    // Wider capabilities than asked.
    let wider = web.replace("caps=", "caps=signet.contacts.read%3Aroles%2C");
    let _ = FakeRail::approve(&net, &wider, RELAY);
    assert!(matches!(next_event(&p), PairingEvent::Failed { .. }));
    assert!(!s.has_contacts_grant());
    let _ = std::fs::remove_dir_all(dir);
}

fn query_param(link: &str, key: &str) -> String {
    let q = link.split_once('?').expect("a query").1;
    q.split('&').find_map(|kv| kv.strip_prefix(&format!("{key}="))).unwrap_or_else(|| panic!("no {key} in {link}")).to_string()
}

#[test]
fn the_link_age_rule_is_more_than_four_minutes() {
    use decented_signet::{PAIRING_LINK_MAX_AGE_SECS, pairing_link_is_stale};
    assert_eq!(PAIRING_LINK_MAX_AGE_SECS, 240);
    assert!(!pairing_link_is_stale(1000, 1000));
    assert!(!pairing_link_is_stale(1000, 1240), "exactly 4 minutes is still fresh");
    assert!(pairing_link_is_stale(1000, 1241));
    assert!(!pairing_link_is_stale(1000, 900), "a clock that went back is not stale");
    // My Signet's own limit is 300 s: the rebuild point leaves room to open the link.
    const { assert!(PAIRING_LINK_MAX_AGE_SECS < decented_signet::contacts_wire::constants::PAIRING_FRESHNESS_SECONDS) };
}

#[test]
fn a_stale_pairing_link_is_rebuilt_with_a_fresh_timestamp_for_the_same_pairing() {
    let net = FakeNetwork::new();
    let dir = temp_dir("pair-stale");
    let s = open(&net, &dir, &Keys::generate());
    let _signer = sign_in_as(&net, &s, &Keys::generate());
    let mut p = s.pair_contacts().unwrap();
    assert_eq!(next_event(&p), PairingEvent::AwaitingApproval);
    let t0 = p.links_built_at();
    let old = p.links().clone();
    assert_eq!(query_param(&old.app_link, "t"), t0.to_string());

    // Fresh enough: left alone.
    assert_eq!(p.refresh_links_if_stale(t0 + 240), Ok(false));
    assert_eq!(p.links(), &old);
    assert_eq!(p.links_built_at(), t0);

    // Over 4 minutes: rebuilt, same app key and challenge, new t, in every form.
    assert_eq!(p.refresh_links_if_stale(t0 + 241), Ok(true));
    let new = p.links();
    assert_ne!(new, &old);
    assert_eq!(p.links_built_at(), t0 + 241);
    for (o, n) in [(&old.app_link, &new.app_link), (&old.web, &new.web), (&old.uri, &new.uri)] {
        assert_eq!(query_param(n, "t"), (t0 + 241).to_string(), "{n}");
        assert_eq!(query_param(n, "app"), query_param(o, "app"));
        assert_eq!(query_param(n, "challenge"), query_param(o, "challenge"));
    }
    // And it is fresh again.
    assert_eq!(p.refresh_links_if_stale(t0 + 241 + 100), Ok(false));
}
