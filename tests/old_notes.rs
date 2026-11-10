//! Old public notes: what the first open after the upgrade collects, and the
//! retraction (one kind 5, `e` tags only) that only ever runs when asked.

mod support;

use std::sync::Arc;
use std::time::Duration;

use decented_signet::relay::FakeNetwork;
use decented_signet::{
    DEFAULT_RELAYS, RelayOutcome, RetractEvent, RetractReport, Retraction, Signet,
};
use nostr::{Event, EventBuilder, EventId, Keys, Kind, Tag, Timestamp};
use serde_json::json;
use support::*;

const T: Duration = Duration::from_secs(10);
/// The relay an old straggler file names as owing a tombstone.
const OWED: &str = "wss://gone.test";

/// What a retraction on the two test relays reports when everything is up:
/// the player's relays, the owed relay (down in `old_phone`), the defaults.
fn expect_all(
    listed: &[&str],
    owed: RelayOutcome,
    listed_outcome: RelayOutcome,
) -> Vec<(String, RelayOutcome)> {
    let mut v: Vec<(String, RelayOutcome)> = listed
        .iter()
        .map(|u| (u.to_string(), listed_outcome))
        .collect();
    v.push((OWED.to_string(), owed));
    v.extend(
        DEFAULT_RELAYS
            .iter()
            .map(|u| (u.to_string(), RelayOutcome::Acked)),
    );
    v
}

/// A phone that ran the version that published: signed in, its attestation
/// public, plus a journal and a straggler tombstone on disk. `Keys` are the
/// persona and the runtime key; the events are what the old version put on
/// the relays.
struct OldPhone {
    dir: std::path::PathBuf,
    persona: Keys,
    runtime: Keys,
    signer: FakeMySignet,
    /// The ids the upgrade must find.
    attestation: Event,
    journal_id: EventId,
    tombstone: Event,
}

impl Drop for OldPhone {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tombstone_of(persona: &Keys) -> Event {
    EventBuilder::new(Kind::Custom(30420), "")
        .tag(Tag::parse(["d", APP_ID]).unwrap())
        .custom_created_at(Timestamp::from(now()))
        .sign_with_keys(persona)
        .unwrap()
}

fn old_phone(net: &FakeNetwork, tag: &str) -> OldPhone {
    let persona = Keys::generate();
    let runtime = Keys::generate();
    let dir = temp_dir(tag);
    let s = open(net, &dir, &runtime);
    let signer = sign_in_as(net, &s, &persona);
    let attestation = s.attestation_event().unwrap();
    drop(s);
    // What the old version had put on the relays.
    net.hub(RELAY).publish(&attestation);
    let tombstone = tombstone_of(&persona);
    // The relay the old straggler file says still owed the tombstone is gone.
    net.hub(OWED).set_offline(true);
    let journal_id = EventId::from_byte_array([9; 32]);
    // What it kept on disk: no marker, a journal, a straggler, the switch and the salt.
    let sd = signet_dir(&dir);
    let _ = std::fs::remove_file(sd.join("old-public-notes.json"));
    std::fs::write(
        sd.join(format!("withdrawal-{}.json", "ab".repeat(32))),
        json!({"persona": persona.public_key().to_hex(), "d_tag": APP_ID, "event_id": journal_id.to_hex()}).to_string(),
    )
    .unwrap();
    std::fs::write(
        sd.join(format!("stragglers-{}.json", "cd".repeat(32))),
        json!({"tombstone": tombstone, "relays": ["wss://gone.test"]}).to_string(),
    )
    .unwrap();
    std::fs::write(
        sd.join("personas.json"),
        json!({"v": 1, "unknown_default": false, "records": {}}).to_string(),
    )
    .unwrap();
    std::fs::write(
        sd.join("device-salt.json"),
        json!({"salt": "11".repeat(32)}).to_string(),
    )
    .unwrap();
    std::fs::write(
        sd.join("settings.json"),
        json!({"only_contacts_invite": true}).to_string(),
    )
    .unwrap();
    OldPhone {
        dir,
        persona,
        runtime,
        signer,
        attestation,
        journal_id,
        tombstone,
    }
}

fn asks_30420(r: &decented_signet::relay::FakeReq) -> bool {
    r.filters
        .iter()
        .any(|f| serde_json::to_value(f).unwrap()["kinds"] == json!([30420]))
}

fn sorted(mut v: Vec<EventId>) -> Vec<EventId> {
    v.sort();
    v
}

fn run(r: &Retraction) -> (Vec<RetractEvent>, RetractEvent) {
    let mut seen = Vec::new();
    let deadline = std::time::Instant::now() + T;
    loop {
        while let Some(ev) = r.poll() {
            if matches!(ev, RetractEvent::Finished(_) | RetractEvent::Failed { .. }) {
                return (seen, ev);
            }
            seen.push(ev);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "retraction did not finish: {seen:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn finished(ev: RetractEvent) -> RetractReport {
    match ev {
        RetractEvent::Finished(r) => r,
        other => panic!("{other:?}"),
    }
}

fn kind5(net: &FakeNetwork, url: &str) -> Vec<Event> {
    net.hub(url)
        .published()
        .into_iter()
        .filter(|e| e.kind == Kind::EventDeletion)
        .collect()
}

#[test]
fn the_first_open_after_the_upgrade_collects_every_old_id_and_deletes_the_old_files() {
    let net = FakeNetwork::new();
    let old = old_phone(&net, "upgrade");
    let s = open(&net, &old.dir, &old.runtime);
    assert!(s.is_signed_in(), "the session carries over");
    let want = sorted(vec![old.attestation.id, old.journal_id, old.tombstone.id]);
    assert_eq!(
        sorted(s.old_public_note_ids(&old.persona.public_key())),
        want
    );
    assert_eq!(s.old_public_note_personas(), vec![old.persona.public_key()]);
    // The old discoverability records, journals and stragglers are gone.
    let names: Vec<String> = std::fs::read_dir(signet_dir(&old.dir))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    for gone in ["personas.json", "device-salt.json", "settings.json"] {
        assert!(
            !names.iter().any(|n| n == gone),
            "{gone} survived: {names:?}"
        );
    }
    assert!(
        !names
            .iter()
            .any(|n| n.starts_with("withdrawal-") || n.starts_with("stragglers-")),
        "{names:?}"
    );
    assert!(names.iter().any(|n| n == "old-public-notes.json"));
    // The local attestation (no longer published) and the session stay.
    assert!(s.attestation().is_some());
    // The ids survive a restart, and a second open adds nothing.
    drop(s);
    let again = open(&net, &old.dir, &old.runtime);
    assert_eq!(
        sorted(again.old_public_note_ids(&old.persona.public_key())),
        want
    );
    // Someone else's persona has none.
    assert!(
        again
            .old_public_note_ids(&Keys::generate().public_key())
            .is_empty()
    );
}

#[test]
fn an_attestation_minted_after_the_upgrade_is_not_an_old_note() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let dir = temp_dir("fresh");
    let s = open(&net, &dir, &Keys::generate());
    let _signer = sign_in_as(&net, &s, &persona);
    assert!(s.old_public_note_ids(&persona.public_key()).is_empty());
    drop(s);
    let again = open(&net, &dir, &Keys::generate());
    assert!(again.old_public_note_ids(&persona.public_key()).is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn nothing_retracts_by_itself() {
    let net = FakeNetwork::new();
    let old = old_phone(&net, "never-auto");
    let asked_before = old.signer.stats().signed_kinds.len();
    let s = open(&net, &old.dir, &old.runtime);
    // Launch, resume, refresh the attestation, open the inbox, look up a name, sign in again.
    s.refresh_attestation().wait(T).unwrap().unwrap();
    drop(s.inbox());
    let _ = s.refresh_profile().wait(T);
    drop(open(&net, &old.dir, &old.runtime));
    std::thread::sleep(Duration::from_millis(300));
    assert!(kind5(&net, RELAY).is_empty(), "no kind 5 was published");
    let kinds = old.signer.stats().signed_kinds;
    assert!(
        !kinds[asked_before..].contains(&5),
        "My Signet was never asked to sign a deletion: {kinds:?}"
    );
    // Nobody was asked about the persona's old notes either.
    for url in [RELAY, OWED] {
        assert!(
            net.hub(url).reqs().iter().all(|r| !asks_30420(r)),
            "a 30420 lookup happened without a tap"
        );
    }
    // The old note is still there, and still counted.
    assert!(
        net.hub(RELAY)
            .stored()
            .iter()
            .any(|e| e.id == old.attestation.id)
    );
    assert_eq!(s.old_public_note_ids(&old.persona.public_key()).len(), 3);
}

#[test]
fn the_retraction_is_one_kind_5_with_e_tags_only_sent_to_every_relay() {
    let net = FakeNetwork::new();
    let old = old_phone(&net, "retract");
    net.hub(RELAY_B).publish(&old.attestation);
    let s = open_two_relays(&net, &old.dir, &old.runtime);
    let want = sorted(s.old_public_note_ids(&old.persona.public_key()));
    assert_eq!(want.len(), 3);
    let asked_before = old.signer.stats().signed_kinds.len();

    let (progress, last) = run(&s.retract_old_notes());
    assert_eq!(progress.first(), Some(&RetractEvent::AwaitingSignature));
    assert_eq!(
        progress
            .iter()
            .filter(|e| matches!(e, RetractEvent::Relay { .. }))
            .count(),
        2 + 1 + DEFAULT_RELAYS.len(),
        "{progress:?}"
    );
    let report = finished(last);
    assert_eq!(
        report.relays,
        expect_all(
            &[RELAY, RELAY_B],
            RelayOutcome::Unreachable,
            RelayOutcome::Acked
        )
    );
    assert!(
        report.cleared,
        "the owed relay was down; every reachable one acked"
    );

    // One signature, kind 5.
    let kinds = old.signer.stats().signed_kinds;
    assert_eq!(&kinds[asked_before..], &[5]);
    // The same single event reached both relays and the defaults; it has e tags only.
    let (a, b) = (kind5(&net, RELAY), kind5(&net, RELAY_B));
    assert_eq!((a.len(), b.len()), (1, 1));
    assert_eq!(a[0].id, b[0].id);
    for d in DEFAULT_RELAYS {
        assert_eq!(
            kind5(&net, d).iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![a[0].id]
        );
    }
    assert_eq!(a[0].pubkey, old.persona.public_key());
    assert_eq!(a[0].content, "");
    assert_eq!(a[0].tags.len(), 3);
    for t in a[0].tags.iter() {
        let t = t.as_slice();
        assert_eq!((t.len(), t[0].as_str()), (2, "e"), "e tags only: {t:?}");
    }
    let named: Vec<EventId> = sorted(
        a[0].tags
            .iter()
            .map(|t| EventId::from_hex(&t.as_slice()[1]).unwrap())
            .collect(),
    );
    assert_eq!(named, want);
    // The old attestation is gone from both relays (the fake relay applies NIP-09).
    for url in [RELAY, RELAY_B] {
        assert!(
            !net.hub(url)
                .stored()
                .iter()
                .any(|e| e.id == old.attestation.id),
            "{url}"
        );
    }
    // The ids are dropped, also after a restart; a second call has nothing to do.
    assert!(s.old_public_note_ids(&old.persona.public_key()).is_empty());
    assert!(
        open_two_relays(&net, &old.dir, &old.runtime)
            .old_public_note_ids(&old.persona.public_key())
            .is_empty()
    );
    let (_, last) = run(&s.retract_old_notes());
    assert!(matches!(last, RetractEvent::Failed { .. }));
    assert_eq!(kind5(&net, RELAY).len(), 1);
}

#[test]
fn ids_are_dropped_only_when_every_reachable_relay_acked() {
    let net = FakeNetwork::new();
    let old = old_phone(&net, "partial");
    let s = open_two_relays(&net, &old.dir, &old.runtime);
    let me = old.persona.public_key();

    // One relay down, one acked: the unreachable one does not hold the ids back.
    net.hub(RELAY_B).set_offline(true);
    let report = finished(run(&s.retract_old_notes()).1);
    let mut want = expect_all(
        &[RELAY, RELAY_B],
        RelayOutcome::Unreachable,
        RelayOutcome::Acked,
    );
    want[1].1 = RelayOutcome::Unreachable;
    assert_eq!(report.relays, want);
    assert!(report.cleared);
    assert!(s.old_public_note_ids(&me).is_empty());

    // A fresh phone: one relay refuses -> reachable but not acked -> ids kept.
    let net2 = FakeNetwork::new();
    let old2 = old_phone(&net2, "partial2");
    let s2 = open_two_relays(&net2, &old2.dir, &old2.runtime);
    net2.hub(RELAY_B).set_refusing(true);
    let report = finished(run(&s2.retract_old_notes()).1);
    assert_eq!(
        report.relays[1],
        (RELAY_B.to_string(), RelayOutcome::Refused)
    );
    assert!(!report.cleared);
    assert_eq!(
        s2.old_public_note_ids(&old2.persona.public_key()).len(),
        3,
        "kept for another try"
    );
    // The relay comes round; trying again clears them.
    net2.hub(RELAY_B).set_refusing(false);
    let report = finished(run(&s2.retract_old_notes()).1);
    assert!(
        report.cleared && report.acked() == 2 + DEFAULT_RELAYS.len(),
        "{report:?}"
    );
    assert!(
        s2.old_public_note_ids(&old2.persona.public_key())
            .is_empty()
    );

    // Nobody reachable: nothing is dropped.
    let net3 = FakeNetwork::new();
    let old3 = old_phone(&net3, "partial3");
    // (My Signet still answers on the relay the session was made on.)
    let mut c3 = config(&old3.dir);
    c3.relays = vec![RELAY_B.to_string(), "wss://relay-c.test".to_string()];
    let s3 = Signet::with_connector(c3, old3.runtime.clone(), Arc::new(net3.clone()));
    net3.hub(RELAY_B).set_offline(true);
    net3.hub("wss://relay-c.test").set_offline(true);
    for d in DEFAULT_RELAYS {
        net3.hub(d).set_offline(true);
    }
    let report = finished(run(&s3.retract_old_notes()).1);
    assert!(
        report
            .relays
            .iter()
            .all(|(_, o)| *o == RelayOutcome::Unreachable)
    );
    assert!(!report.cleared);
    assert_eq!(s3.old_public_note_ids(&old3.persona.public_key()).len(), 3);
}

#[test]
fn a_denied_signature_sends_nothing_and_keeps_the_ids() {
    let net = FakeNetwork::new();
    let old = old_phone(&net, "deny");
    let s = open(&net, &old.dir, &old.runtime);
    *old.signer.sign.lock().unwrap() = SignMode::Deny;
    let (_, last) = run(&s.retract_old_notes());
    let RetractEvent::Failed { reason } = last else {
        panic!("{last:?}")
    };
    assert!(reason.contains("said no"), "{reason}");
    assert!(kind5(&net, RELAY).is_empty());
    assert_eq!(s.old_public_note_ids(&old.persona.public_key()).len(), 3);
    // My Signet signing something else than the retraction is refused too.
    *old.signer.sign.lock().unwrap() = SignMode::Substitute;
    let (_, last) = run(&s.retract_old_notes());
    assert!(matches!(last, RetractEvent::Failed { .. }), "{last:?}");
    assert!(kind5(&net, RELAY).is_empty());
}

#[test]
fn nothing_to_retract_or_nobody_signed_in_fails_without_sending() {
    let net = FakeNetwork::new();
    // Signed out.
    let loner = open(&net, &temp_dir("loner2"), &Keys::generate());
    let RetractEvent::Failed { reason } = run(&loner.retract_old_notes()).1 else {
        panic!()
    };
    assert!(reason.contains("Sign in"), "{reason}");
    // Signed in, no old notes.
    let p = player(&net, "clean");
    let RetractEvent::Failed { reason } = run(&p.s.retract_old_notes()).1 else {
        panic!()
    };
    assert!(reason.contains("nothing to remove"), "{reason}");
    assert!(kind5(&net, RELAY).is_empty());
    assert_eq!(p.signer.stats().signed_kinds, vec![30420]);
}

#[test]
fn notes_of_another_persona_wait_for_that_persona() {
    let net = FakeNetwork::new();
    let old = old_phone(&net, "other");
    // Someone else is signed in on this phone now: the notes stay for their owner.
    let s = open(&net, &old.dir, &old.runtime);
    s.sign_out().wait(T).unwrap();
    let RetractEvent::Failed { .. } = run(&s.retract_old_notes()).1 else {
        panic!()
    };
    assert_eq!(s.old_public_note_personas(), vec![old.persona.public_key()]);
    let newer = Signet::with_connector(config(&old.dir), Keys::generate(), Arc::new(net.clone()));
    let other = Keys::generate();
    let _sig = sign_in_as(&net, &newer, &other);
    assert!(newer.old_public_note_ids(&other.public_key()).is_empty());
    let RetractEvent::Failed { reason } = run(&newer.retract_old_notes()).1 else {
        panic!()
    };
    assert!(reason.contains("nothing to remove"), "{reason}");
    assert_eq!(
        newer.old_public_note_ids(&old.persona.public_key()).len(),
        3
    );
}

#[test]
fn the_retraction_also_goes_to_the_relays_the_old_version_still_owed() {
    let net = FakeNetwork::new();
    let old = old_phone(&net, "owed");
    // The list was changed since: only RELAY_B now. The old straggler file named OWED.
    net.hub(OWED).set_offline(false);
    net.hub(OWED).publish(&old.tombstone);
    let mut c = config(&old.dir);
    c.relays = vec![RELAY_B.to_string()];
    let s = Signet::with_connector(c, old.runtime.clone(), Arc::new(net.clone()));
    // OWED refuses: reachable, not acked -> the ids are kept for another try.
    net.hub(OWED).set_refusing(true);
    let report = finished(run(&s.retract_old_notes()).1);
    let outcome = |u: &str| report.relays.iter().find(|(r, _)| r == u).map(|(_, o)| *o);
    assert_eq!(outcome(RELAY_B), Some(RelayOutcome::Acked));
    assert_eq!(outcome(OWED), Some(RelayOutcome::Refused));
    for d in DEFAULT_RELAYS {
        assert_eq!(outcome(d), Some(RelayOutcome::Acked), "{d}");
    }
    assert_eq!(
        outcome(RELAY),
        None,
        "relays that were never listed or owed are not asked"
    );
    assert!(!report.cleared);
    assert_eq!(s.old_public_note_ids(&old.persona.public_key()).len(), 3);
    // It comes round: every relay acks, and the persona is done.
    net.hub(OWED).set_refusing(false);
    let report = finished(run(&s.retract_old_notes()).1);
    assert!(report.cleared, "{report:?}");
    assert_eq!(kind5(&net, OWED).len(), 1);
    assert!(
        !net.hub(OWED)
            .stored()
            .iter()
            .any(|e| e.id == old.tombstone.id),
        "the owed tombstone is gone from the relay that still served it"
    );
    assert!(s.old_public_note_personas().is_empty());
    // And it survives a restart: the owed relays are gone with the ids.
    assert!(
        Signet::with_connector(config(&old.dir), old.runtime.clone(), Arc::new(net.clone()))
            .old_public_note_personas()
            .is_empty()
    );
}

/// A phone whose only trace of the old version is a withdrawal journal that
/// names the persona but no event id (the tombstone's id was never stored).
fn journal_only_phone(net: &FakeNetwork, tag: &str) -> OldPhone {
    let old = old_phone(net, tag);
    let sd = signet_dir(&old.dir);
    for f in std::fs::read_dir(&sd).unwrap().flatten() {
        let n = f.file_name().to_string_lossy().into_owned();
        if n.starts_with("attestation.json")
            || n.starts_with("stragglers-")
            || n.starts_with("withdrawal-")
        {
            let _ = std::fs::remove_file(f.path());
        }
    }
    std::fs::write(
        sd.join(format!("withdrawal-{}.json", "ef".repeat(32))),
        json!({"persona": old.persona.public_key().to_hex(), "d_tag": APP_ID}).to_string(),
    )
    .unwrap();
    old
}

#[test]
fn a_persona_with_only_a_journal_is_offered_and_its_note_is_found_on_the_relays() {
    let net = FakeNetwork::new();
    let old = journal_only_phone(&net, "journal-only");
    let me = old.persona.public_key();
    // What is out there: the confirmed tombstone of a v0.3 withdrawal, and an
    // unrelated note of the persona for another app.
    let other_app = EventBuilder::new(Kind::Custom(30420), "")
        .tag(Tag::parse(["d", "othergame"]).unwrap())
        .sign_with_keys(&old.persona)
        .unwrap();
    net.hub(RELAY_B).publish(&old.tombstone);
    net.hub(RELAY_B).publish(&other_app);
    let s = open_two_relays(&net, &old.dir, &old.runtime);
    assert!(s.old_public_note_ids(&me).is_empty(), "no id is known");
    assert_eq!(
        s.old_public_note_personas(),
        vec![me],
        "but it is still offered"
    );
    // Opening, and anything else, asked nobody about 30420.
    drop(s.inbox());
    let _ = s.refresh_profile().wait(T);
    for url in [RELAY, RELAY_B] {
        assert!(net.hub(url).reqs().iter().all(|r| !asks_30420(r)));
    }

    let report = finished(run(&s.retract_old_notes()).1);
    assert!(report.cleared, "{report:?}");
    // The lookup: authors:[persona], kinds:[30420], no #d, and its own connection on each relay.
    for url in [RELAY, RELAY_B] {
        let reqs = net.hub(url).reqs();
        let looks: Vec<_> = reqs.iter().filter(|r| asks_30420(r)).collect();
        assert_eq!(looks.len(), 1, "{url}");
        assert_eq!(looks[0].filters.len(), 1);
        let v = serde_json::to_value(&looks[0].filters[0]).unwrap();
        assert_eq!(v["authors"], json!([me.to_hex()]));
        assert!(v.get("#d").is_none() && v.get("#t").is_none(), "{v}");
        assert!(
            reqs.iter()
                .filter(|r| r.connection == looks[0].connection)
                .all(asks_30420),
            "{url}: the lookup connection carried another REQ"
        );
        assert!(
            reqs.iter()
                .filter(|r| r.connection != looks[0].connection)
                .all(|r| !asks_30420(r))
        );
    }
    // The retraction names the notes of this app that the relays held (the
    // old attestation on one, the tombstone on the other), by e tag only.
    let k5 = kind5(&net, RELAY_B);
    assert_eq!(k5.len(), 1);
    let mut named: Vec<String> = k5[0]
        .tags
        .iter()
        .map(|t| {
            let t = t.as_slice();
            assert_eq!((t.len(), t[0].as_str()), (2, "e"));
            t[1].clone()
        })
        .collect();
    named.sort();
    let mut want = vec![old.attestation.id.to_hex(), old.tombstone.id.to_hex()];
    want.sort();
    assert_eq!(named, want, "another app's note is not named");
    assert!(
        net.hub(RELAY_B)
            .stored()
            .iter()
            .all(|e| e.id != old.tombstone.id)
    );
    assert!(
        net.hub(RELAY_B)
            .stored()
            .iter()
            .any(|e| e.id == other_app.id),
        "another app's note is left alone"
    );
    // Done: the row goes, and it stays gone after a restart.
    assert!(s.old_public_note_personas().is_empty());
    assert!(
        open_two_relays(&net, &old.dir, &old.runtime)
            .old_public_note_personas()
            .is_empty()
    );
}

#[test]
fn a_looked_for_persona_with_nothing_out_there_is_done_without_a_signature() {
    let net = FakeNetwork::new();
    let old = journal_only_phone(&net, "nothing-out-there");
    // The old attestation has been taken down already (NIP-09).
    let cleanup = EventBuilder::new(Kind::EventDeletion, "")
        .tag(Tag::event(old.attestation.id))
        .sign_with_keys(&old.persona)
        .unwrap();
    assert!(net.hub(RELAY).publish(&cleanup));
    let s = open_two_relays(&net, &old.dir, &old.runtime);
    let asked_before = old.signer.stats().signed_kinds.len();
    let report = finished(run(&s.retract_old_notes()).1);
    assert!(report.cleared, "{report:?}");
    assert_eq!(kind5(&net, RELAY).len(), 1, "only the clean-up above");
    assert!(kind5(&net, RELAY_B).is_empty());
    assert_eq!(
        old.signer.stats().signed_kinds.len(),
        asked_before,
        "nothing to sign"
    );
    assert!(s.old_public_note_personas().is_empty());

    // With every relay unreachable it could not look: the persona stays offered.
    let net2 = FakeNetwork::new();
    let old2 = journal_only_phone(&net2, "nothing-reachable");
    let s2 = open_two_relays(&net2, &old2.dir, &old2.runtime);
    for u in [RELAY, RELAY_B].into_iter().chain(DEFAULT_RELAYS) {
        net2.hub(u).set_offline(true);
    }
    let RetractEvent::Failed { reason } = run(&s2.retract_old_notes()).1 else {
        panic!()
    };
    assert!(reason.contains("reach"), "{reason}");
    assert_eq!(
        s2.old_public_note_personas(),
        vec![old2.persona.public_key()]
    );
}

/// A relay that answers every REQ with CLOSED, the way the live worker reports
/// it: the status is `Closed`, one EOSE follows, and it is not counted as
/// unreachable.
struct Refusing;

impl decented_signet::relay::Relay for Refusing {
    fn publish(&self, _: &Event) {}
    fn subscribe(&self, _: Vec<nostr::Filter>) -> decented_signet::relay::Subscription {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let (_stx, srx) = tokio::sync::watch::channel(decented_signet::relay::SubStatus::Closed(
            "rate-limited: slow down".into(),
        ));
        let _ = tx.try_send(decented_signet::relay::RelayMsg::Eose);
        decented_signet::relay::Subscription::new(rx, 1, None).with_status(srx)
    }
    fn urls(&self) -> Vec<String> {
        vec![RELAY_B.to_string()]
    }
}

/// The fake network, with `RELAY_B` refusing every read.
struct RefusingB(FakeNetwork);

impl decented_signet::relay::Connector for RefusingB {
    fn connect(&self, urls: &[String]) -> Arc<dyn decented_signet::relay::Relay> {
        if urls == [RELAY_B.to_string()] {
            Arc::new(Refusing)
        } else {
            decented_signet::relay::Connector::connect(&self.0, urls)
        }
    }
}

/// A relay that refused the lookup has not said it holds nothing: with the
/// rest down, the persona stays offered and nothing is cleared.
#[test]
fn a_relay_that_refused_the_lookup_does_not_count_as_holding_nothing() {
    let net = FakeNetwork::new();
    let old = journal_only_phone(&net, "refused-lookup");
    for u in [RELAY].into_iter().chain(DEFAULT_RELAYS) {
        net.hub(u).set_offline(true);
    }
    let mut c = config(&old.dir);
    c.relays = vec![RELAY.to_string(), RELAY_B.to_string()];
    let s = Signet::with_connector(c, old.runtime.clone(), Arc::new(RefusingB(net.clone())));
    let RetractEvent::Failed { reason } = run(&s.retract_old_notes()).1 else {
        panic!("cleared on a refusal")
    };
    assert!(reason.contains("reach"), "{reason}");
    assert_eq!(
        s.old_public_note_personas(),
        vec![old.persona.public_key()]
    );
}

/// A damaged record of old notes cannot say what was owed. The signed-in
/// persona is still offered the removal (the tap looks on the relays), and
/// the file is rewritten so that survives a restart.
#[test]
fn a_damaged_record_still_offers_the_signed_in_persona_its_removal() {
    let net = FakeNetwork::new();
    let old = old_phone(&net, "damaged-record");
    // The first open migrates and writes the record; then it is damaged.
    drop(open_two_relays(&net, &old.dir, &old.runtime));
    let file = signet_dir(&old.dir).join("old-public-notes.json");
    std::fs::write(&file, b"{torn").unwrap();
    let s = open_two_relays(&net, &old.dir, &old.runtime);
    assert_eq!(s.old_public_note_personas(), vec![old.persona.public_key()]);
    assert!(aside_copies(&old.dir, "old-public-notes.json") >= 1, "the bytes are kept");
    drop(s);
    let again = open_two_relays(&net, &old.dir, &old.runtime);
    assert_eq!(again.old_public_note_personas(), vec![old.persona.public_key()]);
    let report = finished(run(&again.retract_old_notes()).1);
    assert!(report.cleared, "{report:?}");
    assert!(again.old_public_note_personas().is_empty());
}
