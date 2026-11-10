//! Friend links (v0.5.0): live links and their mailbox listener, hellos,
//! accept and decline, the friend reply and the inbox's third acceptance case.
//! Everything runs on the in-memory relay network.

mod support;

use std::time::Duration;

use decented_invite::{FriendLink, Hello, Reply, seal_hello};
use decented_signet::attestation::unsigned_attestation;
use decented_signet::relay::FakeNetwork;
use decented_signet::{
    FRIEND_REPLY_RUMOR_KIND, FriendEvent, MAX_HELLOS_PER_LINK, MAX_HELLOS_PER_SENDER,
    MAX_LIVE_LINKS,
};
use nostr::{EventBuilder, Filter, Keys, Kind, Tag};
use support::*;

const T: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(400);
const DAY: u64 = 86_400;

fn quiet() {
    std::thread::sleep(QUIET);
}

/// Wait for exactly one friend event.
fn added(p: &Player) -> FriendEvent {
    wait_for(T, "friend event", || {
        p.s.take_friend_events().into_iter().next()
    })
}

fn wraps(net: &FakeNetwork) -> usize {
    net.hub(RELAY)
        .published()
        .iter()
        .filter(|e| e.kind == Kind::GiftWrap)
        .count()
}

/// A hand-made install: a persona, a runtime key, and a persona-signed attestation.
struct Ghost {
    persona: Keys,
    runtime: Keys,
    att: String,
}

fn ghost() -> Ghost {
    let (persona, runtime) = (Keys::generate(), Keys::generate());
    let ev = unsigned_attestation(APP_ID, &persona.public_key(), &runtime.public_key(), now())
        .sign_with_keys(&persona)
        .unwrap();
    Ghost {
        persona,
        runtime,
        att: serde_json::to_string(&ev).unwrap(),
    }
}

fn hello_from(g: &Ghost, link: &FriendLink, name: &str) -> nostr::Event {
    let h = Hello::new(link.hash(), name, vec![RELAY.to_string()], g.att.clone()).unwrap();
    seal_hello(&g.runtime, link, &h, APP_ID, now()).unwrap()
}

fn publish(net: &FakeNetwork, ev: &nostr::Event) {
    assert!(net.hub(RELAY).publish(ev));
}

#[test]
fn a_link_is_used_accepted_and_both_books_gain_each_other() {
    let net = FakeNetwork::new();
    let (a, b) = (player(&net, "fl-a"), player(&net, "fl-b"));
    let link = a.s.create_friend_link().unwrap();
    assert_eq!(link.to, a.runtime.public_key());
    assert_eq!(link.relays, a.s.inbox_relays());
    assert_eq!(a.s.friend_links().len(), 1);

    let inbox = b.s.inbox();
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    let pending = b.s.pending_friend_links();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].to, link.to);
    assert_eq!(pending[0].link, link.hash());
    assert_eq!(pending[0].exp, link.exp);

    let hello = wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());
    assert_eq!(hello.persona, b.persona.public_key());
    assert_eq!(hello.runtime, b.runtime.public_key());
    assert_eq!(Some(hello.name.clone()), b.s.friend_name());
    assert_eq!(hello.link, hex::encode(link.hash()));
    assert!(
        a.s.played_with().unwrap().is_empty(),
        "nothing is added without a tap"
    );

    let entry = a.s.accept_hello(&hello.id).wait(T).unwrap().unwrap();
    assert_eq!(entry.persona, b.persona.public_key().to_hex());
    assert_eq!(entry.games, 0, "added by link: no game yet");
    assert!(a.s.friend_hellos().is_empty());

    match added(&b) {
        FriendEvent::Added { persona, .. } => assert_eq!(persona, a.persona.public_key()),
    }
    assert!(b.s.pending_friend_links().is_empty());
    assert!(
        inbox.poll().is_none(),
        "a friend reply is never a game invite"
    );
    let a_in_b =
        b.s.played_with()
            .unwrap()
            .by_persona(&a.persona.public_key())
            .unwrap();
    assert_eq!(a_in_b.runtime, a.runtime.public_key().to_hex());
    assert_eq!(a_in_b.inbox_relays, a.s.inbox_relays());
    assert_eq!(a_in_b.games, 0);
    let b_in_a =
        a.s.played_with()
            .unwrap()
            .by_persona(&b.persona.public_key())
            .unwrap();
    assert_eq!(b_in_a.runtime, b.runtime.public_key().to_hex());
    assert_eq!(b_in_a.inbox_relays, b.s.inbox_relays());

    // The reply's wrap is shaped like any gift wrap: one p tag, a throwaway key.
    let reply = net
        .hub(RELAY)
        .published()
        .into_iter()
        .rfind(|e| e.kind == Kind::GiftWrap)
        .unwrap();
    assert_ne!(reply.pubkey, a.runtime.public_key());
    assert!(reply.tags.iter().any(|t| t.as_slice()[0] == "expiration"));
}

#[test]
fn declining_sends_nothing_and_is_not_asked_again() {
    let net = FakeNetwork::new();
    let (a, b) = (player(&net, "fd-a"), player(&net, "fd-b"));
    let link = a.s.create_friend_link().unwrap();
    let inbox = b.s.inbox();
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    let hello = wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());
    let before = wraps(&net);
    assert!(a.s.decline_hello(&hello.id));
    assert!(!a.s.decline_hello(&hello.id));
    quiet();
    assert_eq!(wraps(&net), before, "a decline publishes nothing");
    assert!(a.s.friend_hellos().is_empty());
    assert!(a.s.played_with().unwrap().is_empty());
    assert!(b.s.take_friend_events().is_empty());
    assert!(inbox.poll().is_none());
    // The same hello again (same content) is not asked about.
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    quiet();
    assert!(a.s.friend_hellos().is_empty());
}

#[test]
fn a_hello_whose_attestation_binds_another_key_is_rejected() {
    let net = FakeNetwork::new();
    let a = player(&net, "fb-a");
    let link = a.s.create_friend_link().unwrap();
    let evil = ghost();
    // Sealed by a key the attestation does not bind (a replay of a real attestation).
    let h = Hello::new(
        link.hash(),
        "Eve",
        vec![RELAY.to_string()],
        evil.att.clone(),
    )
    .unwrap();
    let ev = seal_hello(&Keys::generate(), &link, &h, APP_ID, now()).unwrap();
    publish(&net, &ev);
    // An attestation for another game.
    let other = {
        let (p, r) = (Keys::generate(), Keys::generate());
        let att = unsigned_attestation("othergame", &p.public_key(), &r.public_key(), now())
            .sign_with_keys(&p)
            .unwrap();
        Ghost {
            persona: p,
            runtime: r,
            att: serde_json::to_string(&att).unwrap(),
        }
    };
    publish(&net, &hello_from(&other, &link, "Other"));
    // An attestation that is not signed by anyone it names.
    let forged = {
        let (p, r) = (Keys::generate(), Keys::generate());
        let mut ev = unsigned_attestation(APP_ID, &p.public_key(), &r.public_key(), now())
            .sign_with_keys(&p)
            .unwrap();
        ev.pubkey = Keys::generate().public_key();
        Ghost {
            persona: p,
            runtime: r,
            att: serde_json::to_string(&ev).unwrap(),
        }
    };
    publish(&net, &hello_from(&forged, &link, "Forged"));
    quiet();
    assert!(a.s.friend_hellos().is_empty());
    // The listener is alive: an honest hello still lands.
    let honest = ghost();
    publish(&net, &hello_from(&honest, &link, "Honest"));
    let h = wait_for(T, "honest hello", || a.s.friend_hellos().into_iter().next());
    assert_eq!(h.name, "Honest");
    assert_eq!(h.persona, honest.persona.public_key());
    assert_eq!(a.s.friend_hellos().len(), 1);
}

#[test]
fn a_reply_that_matches_no_pending_link_is_ignored_and_not_an_invite() {
    let net = FakeNetwork::new();
    let (a, b) = (player(&net, "fr-a"), player(&net, "fr-b"));
    let link = a.s.create_friend_link().unwrap();
    let inbox = b.s.inbox();
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());

    let reply_wrap = |signer: &Keys, link_hash: [u8; 32], att: String| {
        let r = Reply::new(link_hash, "Eve", vec![RELAY.to_string()], att).unwrap();
        let rumor = EventBuilder::new(Kind::Custom(FRIEND_REPLY_RUMOR_KIND), r.to_json().unwrap())
            .build(signer.public_key());
        let exp = Tag::parse(["expiration", &(now() + 3600).to_string()]).unwrap();
        futures_block(EventBuilder::gift_wrap(
            signer,
            &b.runtime.public_key(),
            rumor,
            [exp],
        ))
        .unwrap()
    };
    let a_att = a.s.attestation_json().unwrap();
    // 1. Sealed by another key, carrying A's genuine attestation (it binds A's key, not the signer).
    publish(
        &net,
        &reply_wrap(&Keys::generate(), link.hash(), a_att.clone()),
    );
    // 2. Sealed by A's key, but for a link B never used.
    publish(&net, &reply_wrap(&a.runtime, [7u8; 32], a_att.clone()));
    // 3. A stranger's own valid attestation, right link hash, wrong key for `to`.
    let eve = ghost();
    publish(
        &net,
        &reply_wrap(&eve.runtime, link.hash(), eve.att.clone()),
    );
    quiet();
    assert!(b.s.take_friend_events().is_empty());
    assert!(b.s.played_with().unwrap().is_empty());
    assert_eq!(b.s.pending_friend_links().len(), 1);
    assert!(inbox.poll().is_none(), "a reply is not shown as an invite");

    // The genuine reply still works afterwards.
    let hello = a.s.friend_hellos().remove(0);
    a.s.accept_hello(&hello.id).wait(T).unwrap().unwrap();
    assert!(matches!(added(&b), FriendEvent::Added { .. }));
    assert_eq!(b.s.played_with().unwrap().len(), 1);
}

/// A gift wrap from `from`'s runtime key to `to`'s, with a rumor of `kind` and `content`.
fn wrap_to(from: &Player, to: &Player, kind: u16, content: String) -> nostr::Event {
    let rumor = EventBuilder::new(Kind::Custom(kind), content).build(from.runtime.public_key());
    let exp = Tag::parse(["expiration", &(now() + 3600).to_string()]).unwrap();
    futures_block(EventBuilder::gift_wrap(
        &from.runtime,
        &to.runtime.public_key(),
        rumor,
        [exp],
    ))
    .unwrap()
}

#[test]
fn friend_replies_and_game_invites_never_cross() {
    let net = FakeNetwork::new();
    let (a, b) = (player(&net, "fg-a"), player(&net, "fg-b"));
    let link = a.s.create_friend_link().unwrap();
    let inbox = b.s.inbox();
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    // The two know each other, so a game invite *is* accepted on the invite
    // path: only the rumor-kind dispatch keeps the two paths apart.
    meet(&a, &b, "B");
    meet(&b, &a, "A");

    // A genuine game invite, while B has a pending link to A: delivered as an
    // invite, and it is not taken as a reply.
    send(&a, &b);
    let inv = wait_for(T, "invite", || inbox.poll());
    assert_eq!(inv.persona, a.persona.public_key());
    assert!(b.s.take_friend_events().is_empty());
    assert_eq!(
        b.s.pending_friend_links().len(),
        1,
        "the pending link stays"
    );

    // A kind-20913 rumor carrying invite JSON is not an invite (and not a reply).
    let a_att = a.s.attestation_json().unwrap();
    let invite_json = serde_json::json!({
        "v": 2, "host_name": "Mum", "code": "ABCDEF",
        "expires_at": now() + 600, "attestation": a_att,
    })
    .to_string();
    publish(&net, &wrap_to(&a, &b, FRIEND_REPLY_RUMOR_KIND, invite_json));
    // A kind-20912 (invite) rumor carrying reply JSON is not an invite or a reply.
    let reply_json = Reply::new(link.hash(), "A", vec![RELAY.to_string()], a_att)
        .unwrap()
        .to_json()
        .unwrap();
    publish(&net, &wrap_to(&a, &b, 20912, reply_json));
    // Positive on the same inbox afterwards, so the quiet above means "dropped".
    send(&a, &b);
    wait_for(T, "second invite", || inbox.poll());
    assert!(
        inbox.poll().is_none(),
        "the dressed-up wraps were not invites"
    );
    assert!(b.s.take_friend_events().is_empty());
    assert_eq!(b.s.pending_friend_links().len(), 1);

    // And the real reply, from a sender that is in B's book, is no invite.
    let hello = wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());
    a.s.accept_hello(&hello.id).wait(T).unwrap().unwrap();
    assert!(matches!(added(&b), FriendEvent::Added { .. }));
    quiet();
    assert!(
        inbox.poll().is_none(),
        "a friend reply is never a game invite"
    );
}

#[test]
fn a_hello_cannot_be_added_after_its_link_lapses_or_is_cancelled() {
    let net = FakeNetwork::new();
    let a = player(&net, "fx-a");
    let link = a.s.create_friend_link().unwrap();
    let (g1, g2) = (ghost(), ghost());
    publish(&net, &hello_from(&g1, &link, "Late"));
    publish(&net, &hello_from(&g2, &link, "Gone"));
    wait_for(T, "two", || (a.s.friend_hellos().len() == 2).then_some(()));
    let late = a.s.friend_hellos().remove(0);
    // Past the link's expiry: refused, nothing added, nothing sent, the row goes.
    let before = wraps(&net);
    let e =
        a.s.accept_hello_at(&late.id, link.exp + 1)
            .wait(T)
            .unwrap()
            .unwrap_err();
    assert!(e.contains("expired"), "{e}");
    assert!(a.s.played_with().unwrap().is_empty());
    assert_eq!(wraps(&net), before);
    assert_eq!(a.s.friend_hellos().len(), 1);
    // A cancelled link takes its waiting hellos with it.
    assert!(a.s.cancel_friend_link(&link.hash()));
    assert!(a.s.friend_hellos().is_empty());
    let e = a.s.accept_hello(&late.id).wait(T).unwrap().unwrap_err();
    assert!(e.contains("gone"), "{e}");
    assert!(a.s.played_with().unwrap().is_empty());
}

#[test]
fn the_hello_names_its_persona_so_the_name_is_only_a_claim() {
    let net = FakeNetwork::new();
    let a = player(&net, "fn-a");
    let link = a.s.create_friend_link().unwrap();
    let stranger = ghost();
    publish(&net, &hello_from(&stranger, &link, "Mum"));
    let h = wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());
    assert_eq!(h.name, "Mum");
    assert_eq!(h.persona, stranger.persona.public_key());
    assert_eq!(h.runtime, stranger.runtime.public_key());
}

#[test]
fn a_decline_sticks_to_the_signer_and_the_persona_across_a_reopen() {
    let net = FakeNetwork::new();
    let mut a = player(&net, "fn2-a");
    let link = a.s.create_friend_link().unwrap();
    let sam = ghost();
    publish(&net, &hello_from(&sam, &link, "Sam"));
    let h = wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());
    assert!(a.s.decline_hello(&h.id));

    // The same signer with a new name (a new hello id), and the same persona on
    // another runtime key: both dropped silently.
    publish(&net, &hello_from(&sam, &link, "Sam again"));
    let other_runtime = Keys::generate();
    let att = unsigned_attestation(
        APP_ID,
        &sam.persona.public_key(),
        &other_runtime.public_key(),
        now(),
    )
    .sign_with_keys(&sam.persona)
    .unwrap();
    let sam2 = Ghost {
        persona: sam.persona.clone(),
        runtime: other_runtime,
        att: serde_json::to_string(&att).unwrap(),
    };
    publish(&net, &hello_from(&sam2, &link, "Sam on a new phone"));
    let kim = ghost();
    publish(&net, &hello_from(&kim, &link, "Kim"));
    let k = wait_for(T, "kim", || a.s.friend_hellos().into_iter().next());
    quiet();
    assert_eq!(k.name, "Kim");
    assert_eq!(a.s.friend_hellos().len(), 1, "Sam is not asked again");

    // After a restart the mailbox replays everything; Sam is still not asked.
    a.s = open(&net, &a.dir, &a.runtime);
    wait_for(T, "kim again", || {
        a.s.friend_hellos()
            .iter()
            .any(|h| h.name == "Kim")
            .then_some(())
    });
    quiet();
    assert_eq!(a.s.friend_hellos().len(), 1);
}

#[test]
fn a_full_link_gets_its_dropped_hello_back_when_a_slot_frees() {
    let net = FakeNetwork::new();
    let a = player(&net, "ff-a");
    let link = a.s.create_friend_link().unwrap();
    for i in 0..MAX_HELLOS_PER_LINK {
        publish(&net, &hello_from(&ghost(), &link, &format!("Junk {i}")));
    }
    wait_for(T, "full", || {
        (a.s.friend_hellos().len() == MAX_HELLOS_PER_LINK).then_some(())
    });
    publish(&net, &hello_from(&ghost(), &link, "Real friend"));
    quiet();
    assert_eq!(a.s.friend_hellos().len(), MAX_HELLOS_PER_LINK);
    assert!(!a.s.friend_hellos().iter().any(|h| h.name == "Real friend"));
    // One junk row is declined: the mailbox is asked again and the real hello arrives.
    let junk = a.s.friend_hellos().remove(0);
    assert!(a.s.decline_hello(&junk.id));
    wait_for(T, "real friend", || {
        a.s.friend_hellos()
            .iter()
            .any(|h| h.name == "Real friend")
            .then_some(())
    });
    assert_eq!(a.s.friend_hellos().len(), MAX_HELLOS_PER_LINK);
    assert!(
        !a.s.friend_hellos().iter().any(|h| h.id == junk.id),
        "the declined hello does not come back"
    );
}

#[test]
fn a_reply_that_could_not_be_sent_is_owed_and_goes_out_at_the_next_launch() {
    let net = FakeNetwork::new();
    let (mut a, b) = (player(&net, "fw-a"), player(&net, "fw-b"));
    let link = a.s.create_friend_link().unwrap();
    let _inbox = b.s.inbox();
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());

    // A restarts onto relays that never ack a gift wrap: the add works, the reply does not.
    a.s = open_dropping(&net, &a.dir, &a.runtime, &[Kind::GiftWrap]);
    let hello = wait_for(T, "hello again", || a.s.friend_hellos().into_iter().next());
    let e = a.s.accept_hello(&hello.id).wait(T).unwrap().unwrap_err();
    assert!(e.starts_with("Added, but"), "{e}");
    assert_eq!(a.s.played_with().unwrap().len(), 1, "they are in the book");
    quiet();
    assert!(b.s.take_friend_events().is_empty());
    assert_eq!(b.s.pending_friend_links().len(), 1);

    // Next launch, on working relays: the owed reply is sent without a tap.
    a.s = open(&net, &a.dir, &a.runtime);
    match added(&b) {
        FriendEvent::Added { persona, .. } => assert_eq!(persona, a.persona.public_key()),
    }
    assert!(b.s.pending_friend_links().is_empty());
}

#[test]
fn a_repeat_hello_from_someone_added_resends_the_reply_at_most_hourly() {
    let net = FakeNetwork::new();
    let (mut a, b) = (player(&net, "fz-a"), player(&net, "fz-b"));
    let link = a.s.create_friend_link().unwrap();
    let _inbox = b.s.inbox();
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    let hello = wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());
    a.s.accept_hello(&hello.id).wait(T).unwrap().unwrap();
    added(&b);
    let sent = wraps(&net);

    // B writes again straight away: an hour has not passed, so no second reply.
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    quiet();
    assert_eq!(wraps(&net), sent + 1, "just B's hello");
    assert!(a.s.friend_hellos().is_empty(), "not asked a second time");

    // An hour on (the record says the last reply was long ago): a restart
    // replays B's hello and the reply goes out again, once.
    let file = signet_dir(&a.dir).join("friend-links.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(v["accepted"].as_array().unwrap().len(), 1);
    v["accepted"][0]["last_reply"] = 0.into();
    std::fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    a.s = open(&net, &a.dir, &a.runtime);
    wait_for(T, "resent", || (wraps(&net) > sent + 1).then_some(()));
    quiet();
    let after = wraps(&net);
    assert_eq!(after, sent + 2, "one resend for the two hellos");
    a.s = open(&net, &a.dir, &a.runtime);
    quiet();
    assert_eq!(wraps(&net), after, "and not again within the hour");
    assert!(a.s.friend_hellos().is_empty());
}

#[test]
fn a_relay_replaying_the_answered_hello_is_not_the_friend_writing_again() {
    let net = FakeNetwork::new();
    let (mut a, b) = (player(&net, "fy-a"), player(&net, "fy-b"));
    let link = a.s.create_friend_link().unwrap();
    let _inbox = b.s.inbox();
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    let hello = wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());
    a.s.accept_hello(&hello.id).wait(T).unwrap().unwrap();
    added(&b);
    let sent = wraps(&net);
    // Even with the hour long past, each launch replays B's old wrap: no resend.
    let file = signet_dir(&a.dir).join("friend-links.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    v["accepted"][0]["last_reply"] = 0.into();
    std::fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    a.s = open(&net, &a.dir, &a.runtime);
    quiet();
    assert_eq!(wraps(&net), sent);
    assert!(a.s.friend_hellos().is_empty());
}

#[test]
fn the_mailbox_listener_has_its_own_connection_and_looks_back_two_days() {
    let net = FakeNetwork::new();
    let a = player(&net, "fq-a");
    let inbox = a.s.inbox();
    let link = a.s.create_friend_link().unwrap();
    let live = a.s.friend_links().remove(0);
    let mailbox = link.mailbox(APP_ID).unwrap().public_key();
    let hub = net.hub(RELAY);
    let is_mailbox = |f: &Filter| {
        let v = serde_json::to_value(f).unwrap();
        v["#p"] == serde_json::json!([mailbox.to_hex()])
    };
    let is_inbox = |f: &Filter| {
        let v = serde_json::to_value(f).unwrap();
        v["#p"] == serde_json::json!([a.runtime.public_key().to_hex()])
    };
    let req = wait_for(T, "mailbox REQ", || {
        hub.reqs()
            .into_iter()
            .find(|r| r.filters.iter().any(is_mailbox))
    });
    let v = serde_json::to_value(&req.filters[0]).unwrap();
    assert_eq!(v["kinds"], serde_json::json!([1059]));
    assert_eq!(v["since"].as_u64().unwrap(), live.created_at - 2 * DAY);
    assert_eq!(req.filters.len(), 1);
    let inbox_req = wait_for(T, "inbox REQ", || {
        hub.reqs()
            .into_iter()
            .find(|r| r.filters.iter().any(is_inbox))
    });
    assert_ne!(
        req.connection, inbox_req.connection,
        "not the invite inbox's connection"
    );
    // Nothing else rides on the mailbox connection, and the mailbox key is not asked of the others.
    for r in hub.reqs() {
        if r.connection == req.connection {
            assert!(r.filters.iter().all(is_mailbox));
        } else {
            assert!(!r.filters.iter().any(is_mailbox));
        }
    }
    drop(inbox);
}

#[test]
fn sign_out_drops_live_links_and_says_how_many() {
    let net = FakeNetwork::new();
    let a = player(&net, "fs-a");
    a.s.create_friend_link().unwrap();
    a.s.create_friend_link().unwrap();
    assert_eq!(a.s.friend_links().len(), 2);
    let subs = net.hub(RELAY).open_subscriptions();
    let out = a.s.sign_out().wait(T).unwrap();
    assert_eq!(out.friend_links_dropped, 2);
    assert!(a.s.friend_links().is_empty());
    assert!(a.s.friend_hellos().is_empty());
    assert!(a.s.create_friend_link().is_err());
    // The listeners are gone, and a new install on this folder finds no file.
    wait_for(T, "listeners closed", || {
        (net.hub(RELAY).open_subscriptions() + 2 <= subs).then_some(())
    });
    let again = open(&net, &a.dir, &Keys::generate());
    assert!(again.friend_links().is_empty());
    assert_eq!(again.friend_links_dropped_at_open(), 0);
    // Signing out with nothing live reports zero.
    let b = player(&net, "fs-b");
    assert_eq!(b.s.sign_out().wait(T).unwrap().friend_links_dropped, 0);
}

#[test]
fn a_new_runtime_key_drops_the_links_kept_for_the_old_one() {
    let net = FakeNetwork::new();
    let a = player(&net, "fk-a");
    a.s.create_friend_link().unwrap();
    let rotated = open(&net, &a.dir, &Keys::generate());
    assert_eq!(rotated.friend_links_dropped_at_open(), 1);
    assert!(rotated.friend_links().is_empty());
}

#[test]
fn at_most_eight_live_links() {
    let net = FakeNetwork::new();
    let a = player(&net, "fc-a");
    let mut hashes = Vec::new();
    for _ in 0..MAX_LIVE_LINKS {
        hashes.push(a.s.create_friend_link().unwrap().hash());
    }
    let e = a.s.create_friend_link().unwrap_err();
    assert!(e.contains('8'), "{e}");
    assert_eq!(a.s.friend_links().len(), MAX_LIVE_LINKS);
    assert!(a.s.cancel_friend_link(&hashes[0]));
    assert!(!a.s.cancel_friend_link(&hashes[0]));
    assert!(a.s.create_friend_link().is_ok());
}

#[test]
fn sixteen_hellos_wait_per_link_and_two_per_sender() {
    let net = FakeNetwork::new();
    let a = player(&net, "fh-a");
    let link = a.s.create_friend_link().unwrap();
    // One sender with five different hellos: two wait.
    let spammer = ghost();
    for i in 0..5 {
        publish(&net, &hello_from(&spammer, &link, &format!("Spam {i}")));
    }
    wait_for(T, "spam", || {
        (a.s.friend_hellos().len() >= MAX_HELLOS_PER_SENDER).then_some(())
    });
    quiet();
    assert_eq!(a.s.friend_hellos().len(), MAX_HELLOS_PER_SENDER);
    // Then many distinct senders: the link fills at 16 and drops the rest.
    for i in 0..(MAX_HELLOS_PER_LINK + 4) {
        publish(&net, &hello_from(&ghost(), &link, &format!("Friend {i}")));
    }
    wait_for(T, "full", || {
        (a.s.friend_hellos().len() >= MAX_HELLOS_PER_LINK).then_some(())
    });
    quiet();
    assert_eq!(a.s.friend_hellos().len(), MAX_HELLOS_PER_LINK);
    // A second link has room of its own.
    let other = a.s.create_friend_link().unwrap();
    publish(&net, &hello_from(&ghost(), &other, "Elsewhere"));
    wait_for(T, "other", || {
        (a.s.friend_hellos().len() > MAX_HELLOS_PER_LINK).then_some(())
    });
}

#[test]
fn handled_ids_and_live_links_survive_a_reopen() {
    let net = FakeNetwork::new();
    let mut a = player(&net, "fp-a");
    let link = a.s.create_friend_link().unwrap();
    let (g1, g2) = (ghost(), ghost());
    publish(&net, &hello_from(&g1, &link, "One"));
    publish(&net, &hello_from(&g2, &link, "Two"));
    wait_for(T, "two", || (a.s.friend_hellos().len() == 2).then_some(()));
    let one =
        a.s.friend_hellos()
            .into_iter()
            .find(|h| h.name == "One")
            .unwrap();
    assert!(a.s.decline_hello(&one.id));

    // Restart: same folder, same runtime key.
    a.s = open(&net, &a.dir, &a.runtime);
    assert_eq!(a.s.friend_links().len(), 1);
    assert_eq!(a.s.friend_links()[0].link.hash(), link.hash());
    let again = wait_for(T, "replayed", || a.s.friend_hellos().into_iter().next());
    quiet();
    assert_eq!(again.name, "Two");
    assert_eq!(
        a.s.friend_hellos().len(),
        1,
        "the declined hello is not asked about again"
    );
    let two = a.s.friend_hellos().remove(0);
    a.s.accept_hello(&two.id).wait(T).unwrap().ok();
    a.s = open(&net, &a.dir, &a.runtime);
    quiet();
    assert!(
        a.s.friend_hellos().is_empty(),
        "an accepted hello is not asked about again either"
    );
}

#[test]
fn your_own_link_is_refused_and_a_pending_link_is_kept_across_a_reopen() {
    let net = FakeNetwork::new();
    let (a, mut b) = (player(&net, "fo-a"), player(&net, "fo-b"));
    let link = a.s.create_friend_link().unwrap();
    assert_eq!(
        a.s.use_friend_link(&link).wait(T).unwrap().unwrap_err(),
        "That's your own friend link."
    );
    assert!(a.s.pending_friend_links().is_empty());
    b.s.use_friend_link(&link).wait(T).unwrap().unwrap();
    b.s = open(&net, &b.dir, &b.runtime);
    assert_eq!(b.s.pending_friend_links().len(), 1);
    // A reply after the restart is still recognised.
    let inbox = b.s.inbox();
    let hello = wait_for(T, "hello", || a.s.friend_hellos().into_iter().next());
    a.s.accept_hello(&hello.id).wait(T).unwrap().unwrap();
    assert!(matches!(added(&b), FriendEvent::Added { .. }));
    assert!(inbox.poll().is_none());
}

/// `EventBuilder::gift_wrap` is async; the tests are not.
fn futures_block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

/// A link names its relays, and anyone can make one. Using it never dials a
/// host on the phone's own network (by name or by address), or anything but
/// `wss://`. A public address is used like any other relay.
#[test]
fn a_link_naming_local_or_ip_relays_does_not_reach_them() {
    let net = FakeNetwork::new();
    let b = player(&net, "fl-local-b");
    let g = ghost();
    let bad = ["wss://192.168.1.1/", "wss://printer.local:8080/"];
    let link = FriendLink::new(
        g.runtime.public_key(),
        bad.iter().map(|u| u.to_string()).collect(),
        APP_ID,
        now(),
        DAY,
    )
    .unwrap();
    let r = b.s.use_friend_link(&link).wait(T).unwrap();
    assert!(r.is_err(), "{r:?}");
    for u in bad {
        assert!(net.hub(u).published().is_empty(), "{u} was sent to");
    }
    assert!(b.s.pending_friend_links().is_empty());

    // A link with one usable relay goes there alone, and only that one is kept.
    let mixed = FriendLink::new(
        g.runtime.public_key(),
        vec!["wss://[::1]/".into(), RELAY.to_string(), "wss://localhost/".into()],
        APP_ID,
        now(),
        DAY,
    )
    .unwrap();
    b.s.use_friend_link(&mixed).wait(T).unwrap().unwrap();
    assert_eq!(wraps(&net), 1);
    assert!(net.hub("wss://[::1]/").published().is_empty());
    assert!(net.hub("wss://localhost/").published().is_empty());
    let pending = b.s.pending_friend_links();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].relays, vec![RELAY.to_string()]);

    // An honest peer may run its relay on a public address: that link is used.
    let public = FriendLink::new(
        ghost().runtime.public_key(),
        vec!["wss://203.0.113.7/".into()],
        APP_ID,
        now(),
        DAY,
    )
    .unwrap();
    b.s.use_friend_link(&public).wait(T).unwrap().unwrap();
    assert_eq!(net.hub("wss://203.0.113.7/").published().len(), 1);
}
