//! In-app invites between installs that have played together: gift wraps to a
//! played-with entry's runtime key, and the receive policy (book, blocks,
//! expiry, forged senders). There is no discovery in this crate; the last
//! tests check that no relay is ever asked about a persona.

mod support;

use std::time::Duration;

use decented_signet::attestation::unsigned_attestation;
use decented_signet::invite::{INVITE_RUMOR_KIND, InviteBody, wrap_invite};
use decented_signet::relay::{Connector, FakeNetwork};
use decented_signet::{DEFAULT_RELAYS, Invite, InvitePayload, SignInEvent};
use nostr::{EventBuilder, Keys, Kind, PublicKey};
use serde_json::{Value, json};
use support::*;

const T: Duration = Duration::from_secs(10);
/// How long we wait to be sure nothing arrives.
const QUIET: Duration = Duration::from_millis(400);

fn quiet(inbox: &decented_signet::InviteInbox) -> Option<Invite> {
    std::thread::sleep(QUIET);
    inbox.poll()
}

/// Two installs that have played together: each is in the other's book.
fn friends(net: &FakeNetwork, a: &str, b: &str) -> (Player, Player) {
    let (x, y) = (player(net, a), player(net, b));
    meet(&x, &y, "Bea");
    meet(&y, &x, "Alex P");
    (x, y)
}

#[test]
fn invite_round_trip_between_people_who_have_played() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alex", "bea");
    let inbox = bea.s.inbox();
    send(&alex, &bea);
    let inv = wait_for(T, "invite", || inbox.poll());
    let want = payload();
    assert_eq!(
        (&inv.payload.host_name, &inv.payload.code),
        (&want.host_name, &want.code)
    );
    assert!(want.expires_at.abs_diff(inv.payload.expires_at) <= 2);
    assert_eq!(inv.persona, alex.persona.public_key());
    assert_eq!(inv.runtime, alex.runtime.public_key());
    assert_eq!(inv.new_runtime, None, "the book already had that key");
    assert_eq!(
        inv.display_sender(),
        "Alex P",
        "named from our book, not the payload's host name"
    );
    assert!(!inv.from_contact());
    assert_eq!(
        inv.attestation,
        alex.s.attestation_json().unwrap(),
        "the sender's attestation rode along"
    );
    assert!(!inv.is_expired(now()));
    assert!(bea.s.still_admits(&inv));

    // What went out: one kind 1059 to Bea's runtime key from a one-time key.
    let wraps = net
        .hub(RELAY)
        .query(&[nostr::Filter::new().kind(Kind::GiftWrap)]);
    assert_eq!(wraps.len(), 1);
    let w = &wraps[0];
    assert_ne!(w.pubkey, alex.runtime.public_key());
    assert_ne!(w.pubkey, alex.persona.public_key());
    assert!(
        w.tags
            .iter()
            .any(|t| t.as_slice() == ["p".to_string(), bea.runtime.public_key().to_hex()])
    );
    assert!(
        w.tags.iter().any(|t| t.as_slice()[0] == "expiration"),
        "NIP-40"
    );
    // The same wrap seen twice (two relays, a reconnect) arrives once.
    net.connect(&[RELAY.to_string()]).publish(w);
    assert!(quiet(&inbox).is_none());
}

#[test]
fn a_stranger_is_dropped_silently_even_if_a_signet_contact() {
    let net = FakeNetwork::new();
    let alex = player(&net, "alexs");
    let bea = player(&net, "beas");
    // Alex has played with Bea (so can send); Bea has not played with Alex.
    meet(&alex, &bea, "Bea");
    give_contacts(
        &net,
        &bea.s,
        json!([contact(
            'a',
            &alex.persona.public_key(),
            "Alex",
            "kin",
            false
        )]),
    );
    let inbox = bea.s.inbox();
    send(&alex, &bea);
    assert!(
        quiet(&inbox).is_none(),
        "a Kin contact who is not in the book is still nobody"
    );
}

#[test]
fn a_blocked_contact_in_the_book_is_dropped() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alexb", "beab");
    give_contacts(
        &net,
        &bea.s,
        json!([contact(
            'a',
            &alex.persona.public_key(),
            "Alex",
            "kin",
            true
        )]),
    );
    let inbox = bea.s.inbox();
    send(&alex, &bea);
    assert!(quiet(&inbox).is_none());
}

#[test]
fn a_block_after_delivery_withdraws_queued_and_shown_invites() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alexq", "beaq");
    let rail = give_contacts(
        &net,
        &bea.s,
        json!([contact(
            'a',
            &alex.persona.public_key(),
            "Alex",
            "kin",
            false
        )]),
    );
    let inbox = bea.s.inbox();
    send(&alex, &bea);
    let shown = wait_for(T, "first invite", || inbox.poll());
    assert!(bea.s.still_admits(&shown));
    assert_eq!(
        shown.display_sender(),
        "Alex",
        "a contact's name beats the book's"
    );
    assert!(shown.from_contact());
    send(&alex, &bea);
    std::thread::sleep(QUIET); // the second is queued, not polled yet
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
    bea.s.refresh_contacts().wait(T).unwrap().unwrap();
    assert!(
        inbox.poll().is_none(),
        "the queued invite is re-checked when polled"
    );
    assert!(!bea.s.still_admits(&shown), "and so is what is on screen");
}

#[test]
fn forgetting_someone_stops_their_invites() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alexf1", "beaf1");
    let inbox = bea.s.inbox();
    send(&alex, &bea);
    let shown = wait_for(T, "invite", || inbox.poll());
    assert_eq!(
        bea.s
            .played_with()
            .unwrap()
            .forget(&alex.persona.public_key()),
        Ok(true)
    );
    assert!(!bea.s.still_admits(&shown));
    send(&alex, &bea);
    assert!(quiet(&inbox).is_none());
}

#[test]
fn a_new_runtime_key_is_admitted_through_its_attestation_and_reported() {
    let net = FakeNetwork::new();
    let alex = player(&net, "alexk");
    let bea = player(&net, "beak");
    meet(&alex, &bea, "Bea");
    // Bea's book holds Alex as they were on an older install key.
    let old_rt = Keys::generate();
    let old_att = unsigned_attestation(
        APP_ID,
        &alex.persona.public_key(),
        &old_rt.public_key(),
        now() - 3_600,
    )
    .sign_with_keys(&alex.persona)
    .unwrap();
    let book = bea.s.played_with().unwrap();
    book.record(
        &serde_json::to_string(&old_att).unwrap(),
        &old_rt.public_key(),
        "Alex P",
        &[],
        now(),
    )
    .unwrap();
    assert!(book.by_runtime(&alex.runtime.public_key()).is_none());

    let inbox = bea.s.inbox();
    send(&alex, &bea);
    let inv = wait_for(T, "invite", || inbox.poll());
    assert_eq!(inv.persona, alex.persona.public_key());
    assert_eq!(inv.new_runtime, Some(alex.runtime.public_key()));
    assert_eq!(inv.display_sender(), "Alex P");
    // The caller updates the entry from what was reported.
    let e = book
        .rekey(&inv.persona, &inv.runtime, &inv.attestation, now())
        .unwrap();
    assert_eq!(e.runtime, alex.runtime.public_key().to_hex());
    assert_eq!(e.games, 1, "no game was counted");
    send(&alex, &bea);
    let again = wait_for(T, "second invite", || inbox.poll());
    assert_eq!(again.new_runtime, None, "now the book knows the key");
}

fn raw_wrap(
    sender: &Keys,
    attestation: &str,
    to: &PublicKey,
    expires_at: u64,
    with_tags: bool,
) -> nostr::Event {
    let rt = tokio::runtime::Runtime::new().unwrap();
    if with_tags {
        let p = InvitePayload {
            host_name: "Alex".into(),
            code: "ABCDEF".into(),
            expires_at,
        };
        rt.block_on(wrap_invite(sender, attestation, to, &p))
            .unwrap()
    } else {
        let body = InviteBody {
            v: 2,
            host_name: "Alex".into(),
            code: "ABCDEF".into(),
            expires_at,
            attestation: attestation.into(),
        };
        let rumor = EventBuilder::new(
            Kind::Custom(INVITE_RUMOR_KIND),
            serde_json::to_string(&body).unwrap(),
        )
        .build(sender.public_key());
        rt.block_on(EventBuilder::gift_wrap(sender, to, rumor, []))
            .unwrap()
    }
}

#[test]
fn expired_invites_are_dropped() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alexe", "beae");
    let inbox = bea.s.inbox();
    let att = alex.s.attestation_json().unwrap();
    let to = bea.runtime.public_key();
    // Relays drop a wrap whose NIP-40 expiration has passed...
    let tagged = raw_wrap(&alex.runtime, &att, &to, now() - 5, true);
    assert!(!net.hub(RELAY).publish(&tagged));
    // ...and one that slips through untagged is dropped by the receiver.
    let untagged = raw_wrap(&alex.runtime, &att, &to, now() - 5, false);
    assert!(net.hub(RELAY).publish(&untagged));
    assert!(quiet(&inbox).is_none());
    // The sender refuses to send one.
    let mut p = payload();
    p.expires_at = now() - 1;
    assert!(
        alex.s
            .send_invite(&entry_of(&alex, &bea), p)
            .wait(T)
            .unwrap()
            .is_err()
    );
    // A live one from the same sender still gets through.
    let live = raw_wrap(&alex.runtime, &att, &to, now() + 60, true);
    assert!(net.hub(RELAY).publish(&live));
    wait_for(T, "live invite", || inbox.poll());
}

#[test]
fn forged_senders_are_dropped() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alexg", "beag");
    let inbox = bea.s.inbox();
    // Alex's attestation reaches every seat in a lobby with Alex. An attacker
    // replays it from their own runtime key to pass as Alex.
    let stolen = alex.s.attestation_json().unwrap();
    let attacker = Keys::generate();
    let forged = raw_wrap(
        &attacker,
        &stolen,
        &bea.runtime.public_key(),
        now() + 60,
        true,
    );
    assert!(net.hub(RELAY).publish(&forged));
    // Or claims Alex with a made-up attestation under Alex's pubkey but another signature.
    let fake_persona = Keys::generate();
    let made_up = unsigned_attestation(
        APP_ID,
        &fake_persona.public_key(),
        &attacker.public_key(),
        now(),
    )
    .sign_with_keys(&fake_persona)
    .unwrap();
    let mut v: Value = serde_json::to_value(&made_up).unwrap();
    v["pubkey"] = json!(alex.persona.public_key().to_hex());
    let forged2 = raw_wrap(
        &attacker,
        &v.to_string(),
        &bea.runtime.public_key(),
        now() + 60,
        true,
    );
    assert!(net.hub(RELAY).publish(&forged2));
    // Or a real, valid attestation of a persona Bea has never played with.
    let nobody = Keys::generate();
    let stranger_att =
        unsigned_attestation(APP_ID, &nobody.public_key(), &attacker.public_key(), now())
            .sign_with_keys(&nobody)
            .unwrap();
    let forged3 = raw_wrap(
        &attacker,
        &serde_json::to_string(&stranger_att).unwrap(),
        &bea.runtime.public_key(),
        now() + 60,
        true,
    );
    assert!(net.hub(RELAY).publish(&forged3));
    assert!(quiet(&inbox).is_none());
    // The inbox is alive: the real Alex gets through.
    send(&alex, &bea);
    assert_eq!(
        wait_for(T, "real invite", || inbox.poll()).persona,
        alex.persona.public_key()
    );
}

#[test]
fn a_stale_attestation_from_an_old_install_cannot_rekey_an_entry() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alexs", "beas");
    let book = bea.s.played_with().unwrap();
    let inbox = bea.s.inbox();
    let to = bea.runtime.public_key();
    let mint = |runtime: &Keys, at: u64| {
        serde_json::to_string(
            &unsigned_attestation(
                APP_ID,
                &alex.persona.public_key(),
                &runtime.public_key(),
                at,
            )
            .sign_with_keys(&alex.persona)
            .unwrap(),
        )
        .unwrap()
    };
    // Alex's old install R1: its attestation (made an hour ago) is still in
    // date, but it is older than the one Bea's book holds. Its invite is a
    // stranger's, and a rekey is refused.
    let r1 = Keys::generate();
    let stale = mint(&r1, now() - 3_600);
    assert!(
        net.hub(RELAY)
            .publish(&raw_wrap(&r1, &stale, &to, now() + 60, true))
    );
    assert!(quiet(&inbox).is_none(), "a stale install is a stranger");
    assert!(
        book.rekey(&alex.persona.public_key(), &r1.public_key(), &stale, now())
            .is_err()
    );
    assert_eq!(
        entry_of(&bea, &alex).runtime,
        alex.runtime.public_key().to_hex(),
        "the entry did not go back"
    );
    // A newer install R3 is admitted, reported, and may rekey.
    let r3 = Keys::generate();
    let fresh = mint(&r3, now() + 5);
    assert!(
        net.hub(RELAY)
            .publish(&raw_wrap(&r3, &fresh, &to, now() + 60, true))
    );
    let inv = wait_for(T, "newer install", || inbox.poll());
    assert_eq!(inv.new_runtime, Some(r3.public_key()));
    let e = book
        .rekey(&inv.persona, &inv.runtime, &inv.attestation, now())
        .unwrap();
    assert_eq!(e.runtime, r3.public_key().to_hex());
    // Now the stale R1 cannot take it back either.
    assert!(
        book.rekey(&alex.persona.public_key(), &r1.public_key(), &stale, now())
            .is_err()
    );
}

#[test]
fn sending_needs_an_attestation_and_a_valid_entry() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alexn", "bean");
    // Signed out and never attested.
    let loner = open(&net, &temp_dir("loner"), &Keys::generate());
    let e = loner
        .send_invite(&entry_of(&alex, &bea), payload())
        .wait(T)
        .unwrap();
    assert!(e.is_err(), "no attestation to carry");
    // An entry with no usable runtime key.
    let mut bad = entry_of(&alex, &bea);
    bad.runtime = "zz".into();
    assert!(
        alex.s
            .send_invite(&bad, payload())
            .wait(T)
            .unwrap()
            .is_err()
    );
    // A malformed payload.
    let mut p = payload();
    p.code = "AB CD".into();
    assert!(
        alex.s
            .send_invite(&entry_of(&alex, &bea), p)
            .wait(T)
            .unwrap()
            .is_err()
    );
    assert!(
        net.hub(RELAY)
            .query(&[nostr::Filter::new().kind(Kind::GiftWrap)])
            .is_empty()
    );
}

#[test]
fn invites_go_to_the_entrys_inbox_relays_and_nowhere_else() {
    let net = FakeNetwork::new();
    let alex = player(&net, "alexr");
    let bea = player(&net, "bear");
    let their_inbox = "wss://their-inbox.test";
    alex.s
        .played_with()
        .unwrap()
        .record(
            &bea.s.attestation_json().unwrap(),
            &bea.runtime.public_key(),
            "Bea",
            &[their_inbox.to_string()],
            now(),
        )
        .unwrap();
    let gift = nostr::Filter::new().kind(Kind::GiftWrap);
    let count = |url: &str| net.hub(url).query(std::slice::from_ref(&gift)).len();
    let everywhere = || {
        [their_inbox, RELAY]
            .into_iter()
            .chain(DEFAULT_RELAYS)
            .map(count)
            .sum::<usize>()
    };

    // Their relay is up: it goes there and only there.
    send(&alex, &bea);
    assert_eq!(
        (count(their_inbox), count(RELAY), count(DEFAULT_RELAYS[0])),
        (1, 0, 0)
    );
    // Their relay is down: no fallback to the defaults (their inbox never
    // reads them), and the host is told.
    net.hub(their_inbox).set_offline(true);
    let r = alex
        .s
        .send_invite(&entry_of(&alex, &bea), payload())
        .wait(T)
        .unwrap();
    assert_eq!(r.unwrap_err(), "couldn't reach their relays");
    assert_eq!(everywhere(), 1, "nothing went anywhere else");

    // An entry with no inbox relays: refused before anything is signed.
    let carol = player(&net, "carolr");
    alex.s
        .played_with()
        .unwrap()
        .record(
            &carol.s.attestation_json().unwrap(),
            &carol.runtime.public_key(),
            "Carol",
            &[],
            now(),
        )
        .unwrap();
    let r = alex
        .s
        .send_invite(&entry_of(&alex, &carol), payload())
        .wait(T)
        .unwrap();
    assert_eq!(r.unwrap_err(), "no inbox relays for this player");
    // Relays that are not valid inbox relays count as none.
    let mut bad = entry_of(&alex, &carol);
    bad.inbox_relays = vec!["ws://plain.test".into(), "wss://localhost".into()];
    let r = alex.s.send_invite(&bad, payload()).wait(T).unwrap();
    assert_eq!(r.unwrap_err(), "no inbox relays for this player");
    assert_eq!(everywhere(), 1, "no wrap was made or sent");
}

// ─── One connection per purpose, and no discovery (kit rules 5 and 7) ──

/// The REQs a relay was asked, as (connection, filter) pairs.
fn asked(net: &FakeNetwork, url: &str) -> Vec<(u64, nostr::Filter)> {
    net.hub(url)
        .reqs()
        .into_iter()
        .flat_map(|r| r.filters.into_iter().map(move |f| (r.connection, f)))
        .collect()
}

fn is_inbox_filter(f: &nostr::Filter, runtime: &PublicKey) -> bool {
    let v = serde_json::to_value(f).unwrap();
    v["kinds"] == json!([1059]) && v["#p"] == json!([runtime.to_hex()])
}

fn is_kind0(f: &nostr::Filter) -> bool {
    serde_json::to_value(f).unwrap()["kinds"] == json!([0])
}

#[test]
fn the_inbox_and_persona_lookups_use_different_connections() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let signer = FakeMySignet::new(&net, persona.clone());
    publish_profile(&net, &persona, r#"{"name":"alex"}"#);
    let other = Keys::generate();
    publish_profile(&net, &other, r#"{"name":"Other"}"#);
    let runtime = Keys::generate();
    let dir = temp_dir("conns");
    let s = open(&net, &dir, &runtime);
    let si = s.sign_in();
    signer.handle_nostrconnect(si.nostrconnect_uri());
    let events = drain_sign_in(&si, T);
    assert!(
        matches!(events.last(), Some(SignInEvent::Attested { .. })),
        "{events:?}"
    );
    assert_eq!(
        s.refresh_profile().wait(T).unwrap().as_deref(),
        Some("alex")
    );
    assert_eq!(
        s.lookup_name(other.public_key())
            .wait(T)
            .unwrap()
            .as_deref(),
        Some("Other")
    );

    let inbox = s.inbox();
    wait_for(T, "the inbox REQ", || {
        asked(&net, RELAY)
            .iter()
            .any(|(_, f)| is_inbox_filter(f, &runtime.public_key()))
            .then_some(())
    });
    drop(inbox);

    let reqs = asked(&net, RELAY);
    let inbox_conns: Vec<u64> = reqs
        .iter()
        .filter(|(_, f)| is_inbox_filter(f, &runtime.public_key()))
        .map(|(c, _)| *c)
        .collect();
    let kind0_conns: Vec<u64> = reqs
        .iter()
        .filter(|(_, f)| is_kind0(f))
        .map(|(c, _)| *c)
        .collect();
    assert_eq!(inbox_conns.len(), 1);
    assert!(kind0_conns.len() >= 2, "own profile and one lookup");
    for c in &kind0_conns {
        assert_ne!(
            *c, inbox_conns[0],
            "the inbox REQ and a kind 0 REQ arrived on the same connection"
        );
    }
    // Nor does the NIP-46 traffic (a persona thing) share the inbox's connection.
    for (c, f) in &reqs {
        if *c == inbox_conns[0] {
            assert!(
                is_inbox_filter(f, &runtime.public_key()),
                "the inbox connection carried {f:?}"
            );
        }
    }
    // And no single REQ names both a persona (authors) and the runtime key.
    for r in net.hub(RELAY).reqs() {
        let v = serde_json::to_value(&r.filters).unwrap();
        let text = v.to_string();
        assert!(
            !(text.contains(&persona.public_key().to_hex())
                && text.contains(&runtime.public_key().to_hex())),
            "{text}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// The single author of a kind 0 REQ, hex.
fn kind0_author(f: &nostr::Filter) -> Option<String> {
    let v = serde_json::to_value(f).ok()?;
    if v["kinds"] != json!([0]) {
        return None;
    }
    let a = v["authors"].as_array()?;
    assert_eq!(a.len(), 1, "one author per request: {v}");
    Some(a[0].as_str()?.to_string())
}

#[test]
fn kind_0_lookups_ask_for_one_author_each() {
    let net = FakeNetwork::new();
    let alex = player(&net, "alexl");
    publish_profile(&net, &alex.persona, r#"{"name":"Alex"}"#);
    let others: Vec<Keys> = (0..4).map(|_| Keys::generate()).collect();
    for (i, k) in others.iter().enumerate() {
        publish_profile(&net, k, &format!(r#"{{"name":"P{i}"}}"#));
    }
    // The own profile, then four lookups started at once.
    assert_eq!(
        alex.s.refresh_profile().wait(T).unwrap().as_deref(),
        Some("Alex")
    );
    let tasks: Vec<_> = others
        .iter()
        .map(|k| alex.s.lookup_name(k.public_key()))
        .collect();
    for (i, t) in tasks.iter().enumerate() {
        assert_eq!(
            t.wait(T).unwrap().as_deref(),
            Some(format!("P{i}").as_str())
        );
    }
    let reqs = net.hub(RELAY).reqs();
    // Never batched: one filter and one author per REQ.
    for r in reqs.iter().filter(|r| r.filters.iter().any(is_kind0)) {
        assert_eq!(r.filters.len(), 1, "never batched in one REQ");
        assert!(kind0_author(&r.filters[0]).is_some());
    }
    let own = alex.persona.public_key().to_hex();
    let own_conns: Vec<u64> = reqs
        .iter()
        .filter(|r| {
            r.filters
                .iter()
                .any(|f| kind0_author(f).as_deref() == Some(&own))
        })
        .map(|r| r.connection)
        .collect();
    assert!(!own_conns.is_empty(), "the own profile was asked for");
    // Each co-player is asked on a connection of its own...
    let mut seen: Vec<u64> = Vec::new();
    for k in &others {
        let hex = k.public_key().to_hex();
        let conns: Vec<u64> = reqs
            .iter()
            .filter(|r| {
                r.filters
                    .iter()
                    .any(|f| kind0_author(f).as_deref() == Some(&hex))
            })
            .map(|r| r.connection)
            .collect();
        assert_eq!(conns.len(), 1, "one REQ for {hex}");
        // ...not the own persona's, and not another co-player's.
        assert!(
            !own_conns.contains(&conns[0]),
            "shares the own persona's connection"
        );
        assert!(!seen.contains(&conns[0]), "shares a co-player's connection");
        seen.push(conns[0]);
        // And that connection carried nothing else.
        let carried = reqs.iter().filter(|r| r.connection == conns[0]).count();
        assert_eq!(carried, 1, "the lookup connection carried other REQs");
    }
}

#[test]
fn no_relay_is_ever_asked_whether_a_persona_plays() {
    let net = FakeNetwork::new();
    let (alex, bea) = friends(&net, "alexd", "bead");
    let inbox = bea.s.inbox();
    send(&alex, &bea);
    wait_for(T, "invite", || inbox.poll());
    alex.s.refresh_attestation().wait(T).unwrap().unwrap();
    let _ = alex.s.sign_out().wait(T);
    for url in [RELAY] {
        for r in net.hub(url).reqs() {
            for f in &r.filters {
                let v = serde_json::to_value(f).unwrap();
                let kinds = v["kinds"].as_array().cloned().unwrap_or_default();
                assert!(
                    !kinds.contains(&json!(30420)),
                    "asked about attestations: {v}"
                );
                assert!(v.get("#d").is_none(), "asked by d tag: {v}");
                assert!(
                    v.get("#t").is_none() && v.get("#k").is_none() && v.get("#a").is_none(),
                    "{v}"
                );
            }
        }
        // Nothing that names a game was ever published: only NIP-46 traffic and gift wraps.
        for ev in net.hub(url).published() {
            assert!(
                ev.kind == Kind::NostrConnect
                    || ev.kind == Kind::GiftWrap
                    || ev.kind == Kind::Metadata,
                "unexpected publish: kind {}",
                ev.kind.as_u16()
            );
        }
    }
}

/// Records which relay lists were opened with the defaults fallback.
struct Recording {
    net: FakeNetwork,
    mains: std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>,
}

impl Connector for Recording {
    fn connect(&self, urls: &[String]) -> std::sync::Arc<dyn decented_signet::relay::Relay> {
        self.net.connect(urls)
    }
    fn connect_main(&self, urls: &[String]) -> std::sync::Arc<dyn decented_signet::relay::Relay> {
        self.mains.lock().unwrap().push(urls.to_vec());
        self.net.connect(urls)
    }
}

fn asks_wraps(r: &decented_signet::relay::FakeReq) -> bool {
    r.filters.iter().any(|f| {
        f.kinds
            .as_ref()
            .is_some_and(|k| k.contains(&Kind::GiftWrap))
    })
}

/// Senders publish an invite only to the inbox relays the hello named, so the
/// inbox listens there and nowhere else: not on the defaults when those
/// relays fail, and not on relays that cannot be named in a hello.
#[test]
fn the_inbox_listens_only_where_an_invite_can_be_sent() {
    let net = FakeNetwork::new();
    let dir = temp_dir("inbox-where");
    let runtime = Keys::generate();
    {
        let s = open(&net, &dir, &runtime);
        sign_in_as(&net, &s, &Keys::generate());
    }
    let mains = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let reopen = |relays: Vec<String>| {
        let mut c = config(&dir);
        c.relays = relays;
        let conn = Recording {
            net: net.clone(),
            mains: mains.clone(),
        };
        decented_signet::Signet::with_connector(c, runtime.clone(), std::sync::Arc::new(conn))
    };
    // Usable inbox relays: the inbox opens them without the defaults fallback.
    let s = reopen(vec![RELAY.to_string()]);
    let opened = mains.lock().unwrap().len();
    let inbox = s.inbox();
    wait_for(T, "the inbox REQ", || {
        net.hub(RELAY).reqs().iter().any(asks_wraps).then_some(())
    });
    assert_eq!(mains.lock().unwrap().len(), opened, "no defaults fallback");
    drop(inbox);
    drop(s);

    // None that a hello could name: no inbox REQ anywhere.
    let local = "wss://relay.local";
    let s = reopen(vec![local.to_string()]);
    let inbox = s.inbox();
    std::thread::sleep(QUIET);
    assert!(inbox.poll().is_none());
    assert!(!net.hub(local).reqs().iter().any(asks_wraps));
    let _ = std::fs::remove_dir_all(&dir);
}
