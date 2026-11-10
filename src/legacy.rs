//! The store of the versions that published the attestation, and what becomes
//! of it on the first open after the upgrade.
//!
//! Those versions publicly posted a kind 30420 attestation per persona (and a
//! tombstone to withdraw it), and kept a switch, a journal and a salt around
//! that. None of that exists any more. [`migrate`] runs at every open and, the
//! first time, does this:
//!
//! 1. collects the id of every attestation or tombstone the old store says
//!    was published, or might have been, per persona;
//! 2. carries over the "used / retired" status of the **current** runtime key
//!    (the old file hashed keys with a salt that is deleted below, so other
//!    keys cannot be carried over);
//! 3. writes `old-public-notes.json` (the marker) and `runtime-keys.json`;
//! 4. only then deletes the old files.
//!
//! The ids are what [`crate::Signet::retract_old_notes`] later asks the
//! persona to take back, with a kind 5 that names them by `e` tag only. It
//! never runs by itself.
//!
//! Also kept, per persona: the relays an old straggler file said still owed a
//! tombstone (the retraction goes there too), and the fact that the persona
//! had *any* old record (a journal, a stored attestation, a straggler, a
//! discoverability record). A tombstone whose withdrawal was confirmed on
//! every relay left no id on this phone, so such a persona is offered the
//! retraction anyway, and the tap first asks the relays for what is there
//! (see `check`).
//!
//! Not recoverable without that ask: a tombstone whose withdrawal was
//! confirmed on every relay is not stored anywhere, and a journal that names
//! no persona cannot be attributed.

use std::collections::BTreeMap;

use nostr::{Event, Kind, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attestation::ATTESTATION_KIND;
use crate::played_with::valid_inbox_relay;
use crate::store::{self, Loaded, RuntimeKeys, Store};

const SALT: &str = "device-salt.json";
const USED: &str = "used-runtime-keys.json";
const RETIRED: &str = "retired-keys.json";
const RETIRED_RAW: &str = "retired-runtime-keys.json";
const PERSONAS: &str = "personas.json";
const SETTINGS: &str = "settings.json";
const JOURNAL_PREFIX: &str = "withdrawal-";
const STRAGGLER_PREFIX: &str = "stragglers-";
/// Most ids kept per persona.
pub(crate) const MAX_IDS: usize = 200;
/// Most owed relays kept per persona.
const MAX_RELAYS: usize = 16;

/// `old-public-notes.json`: persona (hex) to the event ids (hex) of notes an
/// earlier version published.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OldNotes {
    pub v: u32,
    pub notes: BTreeMap<String, Vec<String>>,
    /// Persona (hex) to the relays an earlier version still owed a tombstone
    /// to (wss URLs). The retraction goes there as well.
    #[serde(default)]
    pub relays: BTreeMap<String, Vec<String>>,
    /// Personas (hex) the earlier version left any record for, whether or not
    /// an id was kept. Their notes are looked for on the relays at the tap.
    #[serde(default)]
    pub check: Vec<String>,
}

impl OldNotes {
    /// `persona`: who is signed in, if anyone.
    pub fn load(store: &Store, persona: Option<&PublicKey>) -> OldNotes {
        match store.load_keep::<OldNotes>(store::OLD_PUBLIC_NOTES) {
            Loaded::Ok(n) => n,
            // A damaged copy is kept aside by the load; what it held cannot be
            // read. The signed-in persona is looked for on the relays at the
            // tap, and the file is rewritten to say so. With nobody signed in
            // it stays in place (so migration does not run again) until then.
            Loaded::Damaged => {
                let mut n = OldNotes::empty();
                let Some(p) = persona else {
                    log::warn!("[signet] old-public-notes.json is damaged; kept until someone signs in");
                    return n;
                };
                n.mark(p);
                match store.save(store::OLD_PUBLIC_NOTES, &n) {
                    Ok(()) => log::warn!(
                        "[signet] old-public-notes.json was damaged; the signed-in persona is looked up again"
                    ),
                    Err(e) => log::warn!("[signet] old-public-notes.json is damaged and was not rewritten: {e}"),
                }
                n
            }
            Loaded::Absent => OldNotes::empty(),
        }
    }

    pub fn empty() -> OldNotes {
        OldNotes {
            v: 1,
            notes: BTreeMap::new(),
            relays: BTreeMap::new(),
            check: Vec::new(),
        }
    }

    /// Every persona with something to take back: an id or a record.
    pub fn personas(&self) -> Vec<String> {
        let mut out: Vec<String> = self.notes.keys().cloned().collect();
        for p in &self.check {
            if !out.contains(p) {
                out.push(p.clone());
            }
        }
        out
    }

    /// Whether the relays should be asked what `persona` has public.
    pub fn needs_check(&self, persona: &PublicKey) -> bool {
        self.check.contains(&persona.to_hex())
    }

    pub fn relays_of(&self, persona: &PublicKey) -> Vec<String> {
        self.relays
            .get(&persona.to_hex())
            .cloned()
            .unwrap_or_default()
    }

    /// Note that `persona` left an old record behind.
    fn mark(&mut self, persona: &PublicKey) {
        let h = persona.to_hex();
        if !self.check.contains(&h) {
            self.check.push(h);
        }
    }

    fn add_relays(&mut self, persona: &PublicKey, urls: &[String]) {
        let list = self.relays.entry(persona.to_hex()).or_default();
        for u in urls {
            if list.len() >= MAX_RELAYS {
                break;
            }
            if valid_inbox_relay(u)
                && !list.iter().any(|l| {
                    decented_relays::normalize_relay_url(l)
                        == decented_relays::normalize_relay_url(u)
                })
            {
                list.push(u.clone());
            }
        }
    }

    /// The retraction of `persona` is done: nothing is left to take back.
    pub fn finish(&mut self, persona: &PublicKey) {
        let h = persona.to_hex();
        self.notes.remove(&h);
        self.relays.remove(&h);
        self.check.retain(|p| *p != h);
    }

    pub fn ids(&self, persona: &PublicKey) -> Vec<String> {
        self.notes
            .get(&persona.to_hex())
            .cloned()
            .unwrap_or_default()
    }

    fn add(&mut self, persona: &PublicKey, id: String) {
        let ids = self.notes.entry(persona.to_hex()).or_default();
        if !ids.contains(&id) && ids.len() < MAX_IDS {
            ids.push(id);
        }
    }
}

fn old_runtime_hash(salt: &[u8; 32], runtime: &PublicKey) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(b"runtime-key");
    h.update(runtime.to_bytes());
    hex::encode(h.finalize())
}

/// Hex of a 64-character hash in a file name (`withdrawal-<hash>.json`).
fn is_hash_name(file: &str, prefix: &str) -> bool {
    file.strip_prefix(prefix)
        .and_then(|r| r.strip_suffix(".json"))
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn old_files(store: &Store) -> Vec<String> {
    let mut out: Vec<String> = [SALT, USED, RETIRED, RETIRED_RAW, PERSONAS, SETTINGS]
        .iter()
        .filter(|f| store.exists(f))
        .map(|f| f.to_string())
        .collect();
    out.extend(
        store
            .files_with_prefix(JOURNAL_PREFIX)
            .into_iter()
            .filter(|f| f == "withdrawal-pending.json" || is_hash_name(f, JOURNAL_PREFIX)),
    );
    out.extend(
        store
            .files_with_prefix(STRAGGLER_PREFIX)
            .into_iter()
            .filter(|f| is_hash_name(f, STRAGGLER_PREFIX)),
    );
    out
}

fn remove_old(store: &Store) {
    for f in old_files(store) {
        store.remove_with_asides(&f);
    }
}

/// An attestation or tombstone event of this game, from `bytes`.
fn game_note(bytes: &[u8], app_id: &str) -> Option<Event> {
    let ev: Event = serde_json::from_slice(bytes).ok()?;
    (ev.kind == Kind::Custom(ATTESTATION_KIND)
        && ev.tags.identifier() == Some(app_id)
        && ev.verify().is_ok())
    .then_some(ev)
}

fn read_json(store: &Store, name: &str) -> Option<serde_json::Value> {
    match store.load_keep::<serde_json::Value>(name) {
        Loaded::Ok(v) => Some(v),
        _ => None,
    }
}

/// `SHA-256(device_salt || persona)`, hex: how the old versions named a
/// persona on disk (its record in `personas.json`, its journal's file name).
fn old_persona_hash(salt: &[u8; 32], persona: &PublicKey) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(persona.to_bytes());
    hex::encode(h.finalize())
}

fn old_salt(store: &Store) -> Option<[u8; 32]> {
    match store.load_keep::<serde_json::Value>(SALT) {
        Loaded::Ok(v) => v
            .get("salt")
            .and_then(|s| s.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok()),
        _ => None,
    }
}

/// Collect every id the old store says was published, or might have been, the
/// relays still owed a tombstone, and the personas that left any record.
/// `session_persona` is the persona the session file names, if any.
fn collect(store: &Store, app_id: &str, session_persona: Option<&PublicKey>) -> (OldNotes, usize) {
    let mut notes = OldNotes::empty();
    let mut anonymous = 0;
    // Names (salted hashes) the old store has any record under.
    let mut hashes: Vec<String> = Vec::new();
    // The stored attestation (and aside copies of it): published unless the
    // persona never turned the switch on, and nobody can tell which.
    let mut paths = vec![store.dir().join(store::ATTESTATION)];
    paths.extend(store.aside_copies(store::ATTESTATION));
    for path in paths {
        if let Some(ev) = std::fs::read(path).ok().and_then(|b| game_note(&b, app_id)) {
            notes.add(&ev.pubkey, ev.id.to_hex());
            notes.mark(&ev.pubkey);
        }
    }
    // Withdrawal journals: the attestation they were withdrawing.
    for file in store.files_with_prefix(JOURNAL_PREFIX) {
        if file != "withdrawal-pending.json" && !is_hash_name(&file, JOURNAL_PREFIX) {
            continue;
        }
        if is_hash_name(&file, JOURNAL_PREFIX) {
            hashes.push(file[JOURNAL_PREFIX.len()..file.len() - 5].to_string());
        }
        let Some(v) = read_json(store, &file) else {
            continue;
        };
        let persona = v
            .get("persona")
            .and_then(|x| x.as_str())
            .and_then(|h| PublicKey::from_hex(h).ok());
        let id = v
            .get("event_id")
            .and_then(|x| x.as_str())
            .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
        if let Some(p) = &persona {
            // A journal means a tombstone may be out there, with an id or not.
            notes.mark(p);
        }
        match (persona, id) {
            (Some(p), Some(id)) => notes.add(&p, id.to_string()),
            (None, Some(_)) => anonymous += 1,
            _ => {}
        }
    }
    // Stragglers: a signed tombstone some relays never took, but others may have.
    for file in store.files_with_prefix(STRAGGLER_PREFIX) {
        if !is_hash_name(&file, STRAGGLER_PREFIX) {
            continue;
        }
        hashes.push(file[STRAGGLER_PREFIX.len()..file.len() - 5].to_string());
        let Some(v) = read_json(store, &file) else {
            continue;
        };
        if let Some(ev) = v
            .get("tombstone")
            .and_then(|t| serde_json::from_value::<Event>(t.clone()).ok())
            && ev.kind == Kind::Custom(ATTESTATION_KIND)
            && ev.tags.identifier() == Some(app_id)
        {
            notes.add(&ev.pubkey, ev.id.to_hex());
            notes.mark(&ev.pubkey);
            // The relays that still owed it.
            let owed: Vec<String> = v
                .get("relays")
                .and_then(|r| r.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|u| u.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            notes.add_relays(&ev.pubkey, &owed);
        }
    }
    // The per-persona discoverability records: keyed by salted hash, so they
    // can only be matched to the persona the session names.
    if let Some(Loaded::Ok(v)) = store
        .exists(PERSONAS)
        .then(|| store.load_keep::<serde_json::Value>(PERSONAS))
        && let Some(records) = v.get("records").and_then(|r| r.as_object())
    {
        hashes.extend(records.keys().cloned());
    } else if store.exists(PERSONAS) {
        // A record file that cannot be read: it may hold any persona's record.
        hashes.push(String::new());
    }
    if let Some(me) = session_persona
        && !hashes.is_empty()
    {
        let named = match old_salt(store) {
            Some(salt) => hashes.contains(&old_persona_hash(&salt, me)),
            // Records but no way to tell whose: the signed-in persona, to be safe.
            None => true,
        };
        if named {
            notes.mark(me);
        }
    }
    (notes, anonymous)
}

/// Whether the old store says `me` was used by a sign-in, or retired. Not
/// being able to tell (a salt that is gone while its hashes are there) counts
/// as used: a key is only ever too cautious.
fn old_key_status(store: &Store, me: &PublicKey) -> (bool, bool) {
    let salt: Option<[u8; 32]> = match store.load_keep::<serde_json::Value>(SALT) {
        Loaded::Ok(v) => v
            .get("salt")
            .and_then(|s| s.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok()),
        _ => None,
    };
    let list = |name: &str| -> Option<Option<Vec<String>>> {
        match store.load_keep::<Vec<String>>(name) {
            Loaded::Ok(l) => Some(Some(l)),
            Loaded::Absent => None,
            Loaded::Damaged => Some(None),
        }
    };
    let (mut used, mut retired) = (false, false);
    let hashed = salt.map(|s| old_runtime_hash(&s, me));
    for (name, flag) in [(USED, &mut used), (RETIRED, &mut retired)] {
        match (list(name), &hashed) {
            (None, _) => {}
            (Some(Some(l)), Some(h)) => *flag |= l.contains(h),
            // Hashes there, but no way to compute ours (or the list is torn).
            (Some(_), _) => *flag = true,
        }
    }
    match list(RETIRED_RAW) {
        None => {}
        Some(Some(raw)) => retired |= raw.contains(&me.to_hex()),
        Some(None) => retired = true,
    }
    (used || retired, retired)
}

/// Run the migration (see the module docs). Cheap when there is nothing to
/// do. Returns how many journals could not be attributed to a persona.
pub(crate) fn migrate(store: &Store, app_id: &str, me: &PublicKey) -> usize {
    if store.exists(store::OLD_PUBLIC_NOTES) {
        // Done before; a crash may have left old files behind.
        remove_old(store);
        return 0;
    }
    let session_persona = match store.load_keep::<serde_json::Value>(store::SESSION) {
        Loaded::Ok(v) => v
            .get("persona")
            .and_then(|p| p.as_str())
            .and_then(|h| PublicKey::from_hex(h).ok()),
        _ => None,
    };
    let (notes, anonymous) = collect(store, app_id, session_persona.as_ref());
    let (used, retired) = old_key_status(store, me);
    if used || retired {
        let mut keys = match store.load_keep::<RuntimeKeys>(store::RUNTIME_KEYS) {
            Loaded::Ok(k) => k,
            _ => RuntimeKeys::default(),
        };
        if used {
            keys.add_used(store::runtime_hash(me));
        }
        if retired {
            keys.add_retired(store::runtime_hash(me));
        }
        if let Err(e) = store.save(store::RUNTIME_KEYS, &keys) {
            // Not written: nothing is deleted, and the next open tries again.
            log::warn!("[signet] could not carry over the runtime key status: {e}");
            return anonymous;
        }
    }
    // The marker goes last; the old files are only deleted once it is down.
    if let Err(e) = store.save(store::OLD_PUBLIC_NOTES, &notes) {
        log::warn!("[signet] could not write the old public notes: {e}");
        return anonymous;
    }
    remove_old(store);
    if !notes.personas().is_empty() {
        log::info!(
            "[signet] an earlier version may have published notes for {} persona(s); they can be retracted from Settings",
            notes.personas().len()
        );
    }
    anonymous
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::unsigned_attestation;
    use nostr::Keys;

    const APP: &str = "testgame";

    fn dir(tag: &str) -> std::path::PathBuf {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        std::env::temp_dir().join(format!("decented-signet-legacy-{tag}-{}", hex::encode(b)))
    }

    fn att(persona: &Keys, rt: &Keys, at: u64) -> Event {
        unsigned_attestation(APP, &persona.public_key(), &rt.public_key(), at)
            .sign_with_keys(persona)
            .unwrap()
    }

    fn tombstone(persona: &Keys, at: u64) -> Event {
        nostr::EventBuilder::new(Kind::Custom(ATTESTATION_KIND), "")
            .tag(nostr::Tag::parse(["d", APP]).unwrap())
            .custom_created_at(nostr::Timestamp::from(at))
            .sign_with_keys(persona)
            .unwrap()
    }

    #[test]
    fn migration_collects_every_id_and_deletes_the_old_files() {
        let d = dir("collect");
        let s = Store::new(&d);
        let (p, q, rt, me) = (
            Keys::generate(),
            Keys::generate(),
            Keys::generate(),
            Keys::generate(),
        );
        let a = att(&p, &rt, 1_000);
        let journal_att = att(&p, &rt, 900);
        let tomb = tombstone(&q, 2_000);
        let other_game = unsigned_attestation("othergame", &q.public_key(), &rt.public_key(), 1)
            .sign_with_keys(&q)
            .unwrap();
        s.save(store::ATTESTATION, &a).unwrap();
        // A second copy kept aside from a damaged read.
        std::fs::write(
            d.join("signet/attestation.json.corrupt-5"),
            serde_json::to_vec(&other_game).unwrap(),
        )
        .unwrap();
        s.save(
            "withdrawal-pending.json",
            &serde_json::json!({"persona": "", "event_id": journal_att.id.to_hex()}),
        )
        .unwrap();
        s.save(
            &format!("withdrawal-{}.json", "ab".repeat(32)),
            &serde_json::json!({"persona": p.public_key().to_hex(), "event_id": journal_att.id.to_hex()}),
        )
        .unwrap();
        s.save(
            &format!("stragglers-{}.json", "cd".repeat(32)),
            &serde_json::json!({"tombstone": tomb, "relays": ["wss://x.test"]}),
        )
        .unwrap();
        for f in [SALT, USED, RETIRED, PERSONAS, SETTINGS] {
            s.save(f, &serde_json::json!({})).unwrap();
        }
        s.save(store::SESSION, &serde_json::json!({"keep": "me"}))
            .unwrap();

        let anonymous = migrate(&s, APP, &me.public_key());
        assert_eq!(anonymous, 1);
        let n = OldNotes::load(&s, None);
        let mut mine = n.ids(&p.public_key());
        mine.sort();
        let mut want = vec![a.id.to_hex(), journal_att.id.to_hex()];
        want.sort();
        assert_eq!(mine, want);
        assert_eq!(
            n.ids(&q.public_key()),
            vec![tomb.id.to_hex()],
            "the tombstone, not the other game's note"
        );
        assert!(old_files(&s).is_empty(), "{:?}", old_files(&s));
        assert!(s.exists(store::SESSION), "unrelated files stay");
        // A second open changes nothing.
        let before = OldNotes::load(&s, None);
        assert_eq!(migrate(&s, APP, &me.public_key()), 0);
        assert_eq!(OldNotes::load(&s, None), before);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_fresh_install_gets_an_empty_marker_so_later_attestations_are_not_old_notes() {
        let d = dir("fresh");
        let s = Store::new(&d);
        let me = Keys::generate();
        migrate(&s, APP, &me.public_key());
        assert!(s.exists(store::OLD_PUBLIC_NOTES));
        // The attestation this version stores is local only: a later open must not list it.
        let (p, rt) = (Keys::generate(), Keys::generate());
        s.save(store::ATTESTATION, &att(&p, &rt, 1_000)).unwrap();
        migrate(&s, APP, &me.public_key());
        assert!(OldNotes::load(&s, None).notes.is_empty());
        assert!(s.exists(store::ATTESTATION));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_current_keys_old_status_is_carried_over() {
        let d = dir("keys");
        let s = Store::new(&d);
        let (me, other) = (Keys::generate(), Keys::generate());
        let salt = [7u8; 32];
        s.save(SALT, &serde_json::json!({"salt": hex::encode(salt)}))
            .unwrap();
        s.save(USED, &vec![old_runtime_hash(&salt, &me.public_key())])
            .unwrap();
        migrate(&s, APP, &me.public_key());
        let keys: RuntimeKeys = s.load(store::RUNTIME_KEYS).unwrap();
        assert_eq!(keys.used, vec![store::runtime_hash(&me.public_key())]);
        assert!(keys.retired.is_empty());
        assert!(old_files(&s).is_empty());
        // A key the old store never saw is not marked.
        let d2 = dir("keys2");
        let s2 = Store::new(&d2);
        s2.save(SALT, &serde_json::json!({"salt": hex::encode(salt)}))
            .unwrap();
        s2.save(USED, &vec![old_runtime_hash(&salt, &me.public_key())])
            .unwrap();
        migrate(&s2, APP, &other.public_key());
        assert!(s2.load::<RuntimeKeys>(store::RUNTIME_KEYS).is_none());
        // A retired key is retired (and used).
        let d3 = dir("keys3");
        let s3 = Store::new(&d3);
        s3.save(SALT, &serde_json::json!({"salt": hex::encode(salt)}))
            .unwrap();
        s3.save(RETIRED, &vec![old_runtime_hash(&salt, &me.public_key())])
            .unwrap();
        migrate(&s3, APP, &me.public_key());
        let k3: RuntimeKeys = s3.load(store::RUNTIME_KEYS).unwrap();
        assert_eq!((k3.used.len(), k3.retired.len()), (1, 1));
        // A lost salt next to hashes: the key counts as used.
        let d4 = dir("keys4");
        let s4 = Store::new(&d4);
        s4.save(USED, &vec!["00".repeat(32)]).unwrap();
        migrate(&s4, APP, &me.public_key());
        assert_eq!(
            s4.load::<RuntimeKeys>(store::RUNTIME_KEYS)
                .unwrap()
                .used
                .len(),
            1
        );
        for x in [d, d2, d3, d4] {
            let _ = std::fs::remove_dir_all(x);
        }
    }

    #[test]
    fn finishing_a_persona_drops_everything_kept_for_it() {
        let p = Keys::generate().public_key();
        let mut n = OldNotes::empty();
        n.add(&p, "aa".repeat(32));
        n.add(&p, "bb".repeat(32));
        n.add(&p, "aa".repeat(32));
        assert_eq!(n.ids(&p).len(), 2);
        n.add_relays(
            &p,
            &["wss://one.test".to_string(), "http://no.test".to_string()],
        );
        n.mark(&p);
        assert_eq!(n.relays_of(&p), vec!["wss://one.test".to_string()]);
        assert!(n.needs_check(&p));
        assert_eq!(n.personas(), vec![p.to_hex()]);
        n.finish(&p);
        assert!(n.notes.is_empty() && n.relays.is_empty() && n.check.is_empty());
    }

    #[test]
    fn a_persona_with_only_a_record_or_a_journal_is_marked() {
        let d = dir("marked");
        let s = Store::new(&d);
        let (named, silent, rec_only, other) = (
            Keys::generate(),
            Keys::generate(),
            Keys::generate(),
            Keys::generate(),
        );
        let salt = [7u8; 32];
        // A journal with a persona but no event id; a record for the session's persona.
        s.save(
            &format!(
                "withdrawal-{}.json",
                old_persona_hash(&salt, &named.public_key())
            ),
            &serde_json::json!({"persona": named.public_key().to_hex(), "d_tag": APP}),
        )
        .unwrap();
        s.save(SALT, &serde_json::json!({"salt": hex::encode(salt)}))
            .unwrap();
        s.save(
            PERSONAS,
            &serde_json::json!({"v":1,"unknown_default":false,
              "records": {old_persona_hash(&salt, &rec_only.public_key()): "off"}}),
        )
        .unwrap();
        s.save(
            store::SESSION,
            &serde_json::json!({"app_secret_key":"","remote_signer":"","relays":[],
              "persona": rec_only.public_key().to_hex()}),
        )
        .unwrap();
        migrate(&s, APP, &other.public_key());
        let n = OldNotes::load(&s, None);
        assert!(n.needs_check(&named.public_key()));
        assert!(n.needs_check(&rec_only.public_key()));
        assert!(!n.needs_check(&silent.public_key()));
        assert!(n.notes.is_empty(), "no ids were known");
        let _ = std::fs::remove_dir_all(d);
    }
}
