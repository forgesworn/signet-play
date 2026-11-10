//! The played-with book: who you have shared a game with, kept on this phone.
//!
//! One JSON file per persona, in a directory the caller gives. It is **never
//! published or synced** (kit rule 6). An entry holds what an in-app
//! invite needs to reach that person without asking any relay "does this npub
//! play?": the persona key, the runtime key and the attestation that binds it,
//! the name, up to three inbox relays, and when and how often you played.
//!
//! The book is game-neutral: the app id (the attestation's `d` tag) is given
//! when it is opened.
//!
//! [`PlayedWithBook`] is a cheap-to-clone handle on shared state, so the
//! app's screens and an open [`crate::InviteInbox`] see the same entries.
//! Every change is written to disk atomically (temp file, fsync, rename)
//! before it becomes visible, so a failed write changes nothing.

use std::path::Path;
use std::sync::{Arc, Mutex};

use nostr::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attestation::{AttestationError, created_at_of, verify_attestation};
use crate::contacts_wire::sanitize_wire_text;
use crate::store::Store;

/// Most entries kept; past this the least recently played is dropped.
pub const MAX_ENTRIES: usize = 500;
/// Most inbox relays kept per entry.
pub const MAX_INBOX_RELAYS: usize = 3;
/// Longest inbox relay URL.
pub const MAX_RELAY_URL: usize = 256;
/// Longest name kept.
pub const MAX_NAME: usize = 64;

const FILE_VERSION: u32 = 1;

/// One person you have played with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayedWithEntry {
    /// The persona's public key, hex.
    pub persona: String,
    /// The runtime key of the install they played on, hex. An invite is
    /// gift-wrapped to this key.
    pub runtime: String,
    /// The persona-signed attestation of `runtime`, as event JSON.
    pub attestation: String,
    /// When that attestation lapses (unix seconds).
    pub attestation_expiry: u64,
    /// The name they gave (their hello's, or a kind 0 lookup). May be empty.
    pub name: String,
    /// Up to three `wss://` relays they read invites from.
    pub inbox_relays: Vec<String>,
    /// Unix seconds of the first shared game.
    pub first_played: u64,
    /// Unix seconds of the latest shared game.
    pub last_played: u64,
    /// How many shared games. 0 for a friend added by a friend link who has
    /// not played with you yet.
    pub games: u32,
}

impl PlayedWithEntry {
    pub fn persona_key(&self) -> Option<PublicKey> {
        PublicKey::from_hex(&self.persona).ok()
    }

    pub fn runtime_key(&self) -> Option<PublicKey> {
        PublicKey::from_hex(&self.runtime).ok()
    }
}

/// Why the book refused a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BookError {
    /// The attestation does not verify for that runtime key (signature,
    /// binding, app id or dates).
    BadAttestation(AttestationError),
    /// The attestation is the book owner's own: nobody plays with themselves.
    OwnPersona,
    /// The new state could not be written; nothing changed.
    Save(String),
}

impl std::fmt::Display for BookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BookError::BadAttestation(e) => write!(f, "attestation refused: {e}"),
            BookError::OwnPersona => f.write_str("that is your own persona"),
            BookError::Save(e) => write!(f, "could not save the book: {e}"),
        }
    }
}

impl std::error::Error for BookError {}

#[derive(Serialize, Deserialize)]
struct BookFile {
    v: u32,
    /// The persona this book belongs to, hex.
    owner: String,
    entries: Vec<PlayedWithEntry>,
}

struct Shared {
    store: Store,
    file: String,
    owner: PublicKey,
    app_id: String,
    entries: Vec<PlayedWithEntry>,
}

/// The played-with book of one persona. Clones share the same entries.
#[derive(Clone)]
pub struct PlayedWithBook {
    shared: Arc<Mutex<Shared>>,
}

impl std::fmt::Debug for PlayedWithBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlayedWithBook")
            .field("entries", &self.len())
            .finish()
    }
}

/// `played-with-<first 32 hex of SHA-256(persona)>.json`: the directory does
/// not list personas at a glance.
fn file_name(owner: &PublicKey) -> String {
    let h = Sha256::digest(owner.to_bytes());
    format!("played-with-{}.json", hex::encode(&h[..16]))
}

/// Whether `url` can be an inbox relay: `wss://`, at most [`MAX_RELAY_URL`]
/// characters, a real host, no credentials, no spaces or control characters.
pub fn valid_inbox_relay(url: &str) -> bool {
    if url.len() > MAX_RELAY_URL || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return false;
    }
    if !url.to_ascii_lowercase().starts_with("wss://") {
        return false;
    }
    match nostr::Url::parse(url) {
        Ok(u) => {
            u.scheme() == "wss"
                && u.host_str().is_some_and(|h| !h.is_empty())
                && u.host_str().is_some_and(|h| !is_local_host(h))
                && u.username().is_empty()
                && u.password().is_none()
        }
        Err(_) => false,
    }
}

/// A host on the phone's own network: `localhost`, `*.local`, or an IP
/// literal in a loopback, private, link-local or unspecified range. A
/// co-player's hello must not make this phone dial such a host.
fn is_local_host(host: &str) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    let v4 =
        |a: Ipv4Addr| a.is_loopback() || a.is_private() || a.is_link_local() || a.is_unspecified();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => v4(a),
        Ok(IpAddr::V6(a)) => {
            let seg = a.segments();
            a.is_loopback()
                || a.is_unspecified()
                || (seg[0] & 0xfe00) == 0xfc00 // unique local
                || (seg[0] & 0xffc0) == 0xfe80 // link-local
                || a.to_ipv4_mapped().is_some_and(v4)
        }
        Err(_) => {
            let d = host.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost") || d.ends_with(".local")
        }
    }
}

/// The valid relays of `list`, each once (by [`crate::normalize_relay_url`]),
/// in order, at most [`MAX_INBOX_RELAYS`].
pub fn clean_inbox_relays(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    for u in list {
        if out.len() >= MAX_INBOX_RELAYS {
            break;
        }
        if !valid_inbox_relay(u) {
            continue;
        }
        let k = crate::normalize_relay_url(u);
        if !keys.contains(&k) {
            keys.push(k);
            out.push(u.clone());
        }
    }
    out
}

fn clean_name(name: &str) -> String {
    sanitize_wire_text(name, MAX_NAME)
}

/// Why a different runtime key was not taken: the attestation behind it is not
/// newer than the one the book holds, so it may be an old install's.
pub(crate) const STALE_ATTESTATION: AttestationError =
    AttestationError::Malformed("not newer than the attestation the book holds");

/// Whether `new_attestation` may replace `held` when the runtime key is
/// `different`: a different key needs a strictly newer attestation (by
/// `created_at`); the same key only needs one that is not older. A held
/// attestation that cannot be read counts as the oldest possible.
pub(crate) fn supersedes(held: &str, new_attestation: &str, different: bool) -> bool {
    let old = created_at_of(held).unwrap_or(0);
    let new = created_at_of(new_attestation).unwrap_or(0);
    if different { new > old } else { new >= old }
}

/// Most recent first; equal times: the one first played later is first.
fn sort_recent(entries: &mut [PlayedWithEntry]) {
    entries.sort_by(|a, b| {
        b.last_played
            .cmp(&a.last_played)
            .then(b.first_played.cmp(&a.first_played))
    });
}

impl PlayedWithBook {
    /// Open (or start) `owner`'s book in `dir`. A file that does not parse is
    /// copied aside (`*.corrupt-<unix>`) and left in place until the next
    /// save, and the book starts empty; entries that do not hold valid keys
    /// are skipped, relay lists are cleaned.
    pub fn open(dir: &Path, owner: &PublicKey, app_id: &str) -> PlayedWithBook {
        use crate::store::Loaded;
        let store = Store::in_dir(dir);
        let file = file_name(owner);
        let mut entries: Vec<PlayedWithEntry> = match store.load_keep::<BookFile>(&file) {
            Loaded::Ok(f) if f.v == FILE_VERSION && f.owner == owner.to_hex() => f.entries,
            Loaded::Ok(_) => {
                // A format this version does not know (a downgrade): keep the
                // bytes aside before the next save overwrites them.
                store.set_aside(&file);
                Vec::new()
            }
            Loaded::Damaged | Loaded::Absent => Vec::new(),
        };
        let mut seen: Vec<String> = Vec::new();
        entries.retain(|e| {
            let ok = e.persona_key().is_some()
                && e.runtime_key().is_some()
                && e.persona != owner.to_hex()
                && !seen.contains(&e.persona);
            if ok {
                seen.push(e.persona.clone());
            }
            ok
        });
        for e in &mut entries {
            e.inbox_relays = clean_inbox_relays(&e.inbox_relays);
            e.name = clean_name(&e.name);
        }
        sort_recent(&mut entries);
        entries.truncate(MAX_ENTRIES);
        PlayedWithBook {
            shared: Arc::new(Mutex::new(Shared {
                store,
                file,
                owner: *owner,
                app_id: app_id.to_string(),
                entries,
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The persona this book belongs to.
    pub fn owner(&self) -> PublicKey {
        self.lock().owner
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn save(g: &Shared, entries: &[PlayedWithEntry]) -> Result<(), BookError> {
        let f = BookFile {
            v: FILE_VERSION,
            owner: g.owner.to_hex(),
            entries: entries.to_vec(),
        };
        g.store.save(&g.file, &f).map_err(BookError::Save)
    }

    /// Note a shared game with the persona whose install presented
    /// `attestation_json` for `runtime`.
    ///
    /// The attestation is verified first (the persona signed a binding of
    /// `runtime`, for this game, in date) and the call is refused if it fails.
    /// The persona and the expiry come out of the verified attestation. A new
    /// persona is inserted with one game. A known one gets the new runtime
    /// key, attestation, relays (kept as they were when the new list is empty)
    /// and name (kept when the new one is empty), `games` plus one and
    /// `last_played = now`. Past [`MAX_ENTRIES`] the least recently played
    /// entry is dropped.
    pub fn record(
        &self,
        attestation_json: &str,
        runtime: &PublicKey,
        name: &str,
        inbox_relays: &[String],
        now: u64,
    ) -> Result<PlayedWithEntry, BookError> {
        self.record_inner(attestation_json, runtime, name, inbox_relays, now, true)
    }

    /// [`PlayedWithBook::record`] for a friend added by a friend link, with no
    /// game behind it: a new entry has `games` 0 (`first_played` and
    /// `last_played` are the day it was added), and a known one keeps its
    /// `games` and `last_played`. The first shared game counts as usual.
    pub fn record_link(
        &self,
        attestation_json: &str,
        runtime: &PublicKey,
        name: &str,
        inbox_relays: &[String],
        now: u64,
    ) -> Result<PlayedWithEntry, BookError> {
        self.record_inner(attestation_json, runtime, name, inbox_relays, now, false)
    }

    fn record_inner(
        &self,
        attestation_json: &str,
        runtime: &PublicKey,
        name: &str,
        inbox_relays: &[String],
        now: u64,
        game: bool,
    ) -> Result<PlayedWithEntry, BookError> {
        let mut g = self.lock();
        let info = verify_attestation(&g.app_id, attestation_json, runtime, now)
            .map_err(BookError::BadAttestation)?;
        if info.persona == g.owner {
            return Err(BookError::OwnPersona);
        }
        let persona_hex = info.persona.to_hex();
        let runtime_hex = runtime.to_hex();
        let name = clean_name(name);
        let relays = clean_inbox_relays(inbox_relays);
        let mut entries = g.entries.clone();
        // One runtime key belongs to one persona.
        if entries
            .iter()
            .any(|e| e.runtime == runtime_hex && e.persona != persona_hex)
        {
            return Err(BookError::BadAttestation(AttestationError::WrongRuntimeKey));
        }
        let out = if let Some(e) = entries.iter_mut().find(|e| e.persona == persona_hex) {
            let different = e.runtime != runtime_hex;
            if different && !supersedes(&e.attestation, attestation_json, true) {
                return Err(BookError::BadAttestation(STALE_ATTESTATION));
            }
            if supersedes(&e.attestation, attestation_json, different) {
                e.runtime = runtime_hex;
                e.attestation = attestation_json.to_string();
                e.attestation_expiry = info.valid_until;
            }
            if !relays.is_empty() {
                e.inbox_relays = relays;
            }
            if !name.is_empty() {
                e.name = name;
            }
            if game {
                e.games = e.games.saturating_add(1);
                e.last_played = now;
            }
            e.clone()
        } else {
            let e = PlayedWithEntry {
                persona: persona_hex.clone(),
                runtime: runtime.to_hex(),
                attestation: attestation_json.to_string(),
                attestation_expiry: info.valid_until,
                name,
                inbox_relays: relays,
                first_played: now,
                last_played: now,
                games: u32::from(game),
            };
            entries.push(e.clone());
            e
        };
        while entries.len() > MAX_ENTRIES {
            // The least recently played goes, but never the one just recorded.
            let drop_at = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.persona != persona_hex)
                .min_by_key(|(_, e)| (e.last_played, e.first_played))
                .map(|(i, _)| i);
            match drop_at {
                Some(i) => {
                    entries.remove(i);
                }
                None => break,
            }
        }
        sort_recent(&mut entries);
        Self::save(&g, &entries)?;
        g.entries = entries;
        Ok(out)
    }

    /// An invite from a known persona arrived from a new runtime key, proved
    /// by a fresh attestation: swap the key and attestation in the entry.
    /// Nothing else changes (no game is counted). Refused like
    /// [`PlayedWithBook::record`] if the attestation does not verify for
    /// `runtime`, or if it names a different persona than `persona`; and
    /// refused when the attestation is not strictly newer (by `created_at`)
    /// than the one held and the key differs.
    pub fn rekey(
        &self,
        persona: &PublicKey,
        runtime: &PublicKey,
        attestation_json: &str,
        now: u64,
    ) -> Result<PlayedWithEntry, BookError> {
        let mut g = self.lock();
        let info = verify_attestation(&g.app_id, attestation_json, runtime, now)
            .map_err(BookError::BadAttestation)?;
        if info.persona != *persona {
            return Err(BookError::BadAttestation(AttestationError::WrongRuntimeKey));
        }
        let persona_hex = persona.to_hex();
        let mut entries = g.entries.clone();
        let runtime_hex = runtime.to_hex();
        if entries
            .iter()
            .any(|e| e.runtime == runtime_hex && e.persona != persona_hex)
        {
            return Err(BookError::BadAttestation(AttestationError::WrongRuntimeKey));
        }
        let Some(e) = entries.iter_mut().find(|e| e.persona == persona_hex) else {
            return Err(BookError::BadAttestation(AttestationError::Malformed(
                "not in the book",
            )));
        };
        // A different key needs a strictly newer attestation than the one
        // held; the same key, one that is not older.
        if !supersedes(&e.attestation, attestation_json, e.runtime != runtime_hex) {
            return Err(BookError::BadAttestation(STALE_ATTESTATION));
        }
        e.runtime = runtime_hex;
        e.attestation = attestation_json.to_string();
        e.attestation_expiry = info.valid_until;
        let out = e.clone();
        Self::save(&g, &entries)?;
        g.entries = entries;
        Ok(out)
    }

    /// Store a name for a person who has none (a kind 0 lookup). An empty or
    /// unchanged name changes nothing. `Ok(true)` when the entry was updated.
    pub fn set_name(&self, persona: &PublicKey, name: &str) -> Result<bool, BookError> {
        let mut g = self.lock();
        let name = clean_name(name);
        let persona_hex = persona.to_hex();
        let mut entries = g.entries.clone();
        let Some(e) = entries.iter_mut().find(|e| e.persona == persona_hex) else {
            return Ok(false);
        };
        if name.is_empty() || e.name == name {
            return Ok(false);
        }
        e.name = name;
        Self::save(&g, &entries)?;
        g.entries = entries;
        Ok(true)
    }

    /// Remove one person ("Forget"). `Ok(true)` when they were in the book.
    pub fn forget(&self, persona: &PublicKey) -> Result<bool, BookError> {
        let mut g = self.lock();
        let persona_hex = persona.to_hex();
        let mut entries = g.entries.clone();
        let before = entries.len();
        entries.retain(|e| e.persona != persona_hex);
        if entries.len() == before {
            return Ok(false);
        }
        Self::save(&g, &entries)?;
        g.entries = entries;
        Ok(true)
    }

    /// Everyone, most recently played first.
    pub fn list(&self) -> Vec<PlayedWithEntry> {
        self.lock().entries.clone()
    }

    /// The entry whose current runtime key is `pk`.
    pub fn by_runtime(&self, pk: &PublicKey) -> Option<PlayedWithEntry> {
        let hex = pk.to_hex();
        self.lock()
            .entries
            .iter()
            .find(|e| e.runtime == hex)
            .cloned()
    }

    /// The entry of persona `pk`.
    pub fn by_persona(&self, pk: &PublicKey) -> Option<PlayedWithEntry> {
        let hex = pk.to_hex();
        self.lock()
            .entries
            .iter()
            .find(|e| e.persona == hex)
            .cloned()
    }

    /// Whether the book could not be read back from disk right now (tests).
    #[cfg(test)]
    fn on_disk(&self) -> Option<Vec<PlayedWithEntry>> {
        use crate::store::Loaded;
        let g = self.lock();
        match g.store.load_keep::<BookFile>(&g.file) {
            Loaded::Ok(f) => Some(f.entries),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{VALIDITY_SECS, unsigned_attestation};
    use nostr::Keys;

    const APP: &str = "testgame";
    const NOW: u64 = 1_800_000_000;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        std::env::temp_dir().join(format!("decented-signet-book-{tag}-{}", hex::encode(b)))
    }

    struct Guest {
        persona: Keys,
        runtime: Keys,
    }

    impl Guest {
        fn new() -> Guest {
            Guest {
                persona: Keys::generate(),
                runtime: Keys::generate(),
            }
        }

        fn attestation(&self, at: u64) -> String {
            let ev = unsigned_attestation(
                APP,
                &self.persona.public_key(),
                &self.runtime.public_key(),
                at,
            )
            .sign_with_keys(&self.persona)
            .unwrap();
            serde_json::to_string(&ev).unwrap()
        }

        fn rekeyed(&self) -> Guest {
            Guest {
                persona: self.persona.clone(),
                runtime: Keys::generate(),
            }
        }
    }

    fn open(dir: &Path) -> (PlayedWithBook, Keys) {
        let me = Keys::generate();
        (PlayedWithBook::open(dir, &me.public_key(), APP), me)
    }

    fn relays(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("wss://relay{i}.test")).collect()
    }

    #[test]
    fn record_inserts_then_updates_and_counts_games() {
        let dir = temp_dir("record");
        let (book, _) = open(&dir);
        let g = Guest::new();
        let e = book
            .record(
                &g.attestation(NOW),
                &g.runtime.public_key(),
                "Alex",
                &relays(2),
                NOW,
            )
            .unwrap();
        assert_eq!(e.persona, g.persona.public_key().to_hex());
        assert_eq!(e.runtime, g.runtime.public_key().to_hex());
        assert_eq!((e.games, e.first_played, e.last_played), (1, NOW, NOW));
        assert_eq!(e.attestation_expiry, NOW + VALIDITY_SECS);
        assert_eq!(e.name, "Alex");
        assert_eq!(e.inbox_relays, relays(2));
        assert_eq!(book.len(), 1);

        // A later game on a new install: runtime, attestation, relays, name replaced.
        let g2 = g.rekeyed();
        let att2 = g2.attestation(NOW + 500);
        let e2 = book
            .record(
                &att2,
                &g2.runtime.public_key(),
                "Alex P",
                &relays(3)[1..],
                NOW + 600,
            )
            .unwrap();
        assert_eq!(book.len(), 1);
        assert_eq!(e2.runtime, g2.runtime.public_key().to_hex());
        assert_eq!(e2.attestation, att2);
        assert_eq!(
            (e2.games, e2.first_played, e2.last_played),
            (2, NOW, NOW + 600)
        );
        assert_eq!(e2.name, "Alex P");
        assert_eq!(e2.inbox_relays, relays(3)[1..].to_vec());

        // An empty name or relay list keeps what is there.
        let e3 = book
            .record(&att2, &g2.runtime.public_key(), "  ", &[], NOW + 700)
            .unwrap();
        assert_eq!(
            (e3.name.as_str(), e3.inbox_relays.len(), e3.games),
            ("Alex P", 2, 3)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn record_refuses_what_does_not_verify() {
        let dir = temp_dir("refuse");
        let (book, me) = open(&dir);
        let g = Guest::new();
        // Bound to another runtime key.
        let other = Keys::generate().public_key();
        assert_eq!(
            book.record(&g.attestation(NOW), &other, "x", &[], NOW),
            Err(BookError::BadAttestation(AttestationError::WrongRuntimeKey))
        );
        // Out of date: expired, and not yet valid.
        assert_eq!(
            book.record(
                &g.attestation(NOW),
                &g.runtime.public_key(),
                "x",
                &[],
                NOW + VALIDITY_SECS + 1
            ),
            Err(BookError::BadAttestation(AttestationError::Expired))
        );
        assert_eq!(
            book.record(
                &g.attestation(NOW + 10_000),
                &g.runtime.public_key(),
                "x",
                &[],
                NOW
            ),
            Err(BookError::BadAttestation(AttestationError::NotYetValid))
        );
        // Another game's attestation.
        let ev = unsigned_attestation(
            "othergame",
            &g.persona.public_key(),
            &g.runtime.public_key(),
            NOW,
        )
        .sign_with_keys(&g.persona)
        .unwrap();
        assert_eq!(
            book.record(
                &serde_json::to_string(&ev).unwrap(),
                &g.runtime.public_key(),
                "x",
                &[],
                NOW
            ),
            Err(BookError::BadAttestation(AttestationError::WrongApp))
        );
        // Signed by someone else than the persona it claims (tampered pubkey).
        let mut v: serde_json::Value = serde_json::from_str(&g.attestation(NOW)).unwrap();
        v["pubkey"] = serde_json::json!(Keys::generate().public_key().to_hex());
        assert_eq!(
            book.record(&v.to_string(), &g.runtime.public_key(), "x", &[], NOW),
            Err(BookError::BadAttestation(AttestationError::BadSignature))
        );
        // Garbage.
        assert!(matches!(
            book.record("nope", &g.runtime.public_key(), "x", &[], NOW),
            Err(BookError::BadAttestation(_))
        ));
        // Your own persona.
        let mine = Guest {
            persona: me.clone(),
            runtime: Keys::generate(),
        };
        assert_eq!(
            book.record(
                &mine.attestation(NOW),
                &mine.runtime.public_key(),
                "me",
                &[],
                NOW
            ),
            Err(BookError::OwnPersona)
        );
        assert!(book.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn list_is_most_recent_first_and_lookups_work() {
        let dir = temp_dir("list");
        let (book, _) = open(&dir);
        let (a, b, c) = (Guest::new(), Guest::new(), Guest::new());
        book.record(
            &a.attestation(NOW),
            &a.runtime.public_key(),
            "A",
            &[],
            NOW + 10,
        )
        .unwrap();
        book.record(
            &b.attestation(NOW),
            &b.runtime.public_key(),
            "B",
            &[],
            NOW + 30,
        )
        .unwrap();
        book.record(
            &c.attestation(NOW),
            &c.runtime.public_key(),
            "C",
            &[],
            NOW + 20,
        )
        .unwrap();
        let names: Vec<_> = book.list().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["B", "C", "A"]);
        // Playing with A again brings them to the top.
        book.record(
            &a.attestation(NOW),
            &a.runtime.public_key(),
            "A",
            &[],
            NOW + 40,
        )
        .unwrap();
        assert_eq!(book.list()[0].name, "A");
        assert_eq!(book.by_runtime(&b.runtime.public_key()).unwrap().name, "B");
        assert_eq!(book.by_persona(&c.persona.public_key()).unwrap().name, "C");
        assert!(book.by_runtime(&Keys::generate().public_key()).is_none());
        assert!(book.by_persona(&Keys::generate().public_key()).is_none());
        // A runtime key that was replaced is no longer found.
        let a2 = a.rekeyed();
        book.record(
            &a2.attestation(NOW + 50),
            &a2.runtime.public_key(),
            "A",
            &[],
            NOW + 50,
        )
        .unwrap();
        assert!(book.by_runtime(&a.runtime.public_key()).is_none());
        assert!(book.by_runtime(&a2.runtime.public_key()).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn forget_removes_one_entry_and_survives_a_reopen() {
        let dir = temp_dir("forget");
        let (book, me) = open(&dir);
        let (a, b) = (Guest::new(), Guest::new());
        book.record(&a.attestation(NOW), &a.runtime.public_key(), "A", &[], NOW)
            .unwrap();
        book.record(
            &b.attestation(NOW),
            &b.runtime.public_key(),
            "B",
            &[],
            NOW + 1,
        )
        .unwrap();
        assert_eq!(book.forget(&a.persona.public_key()), Ok(true));
        assert_eq!(book.forget(&a.persona.public_key()), Ok(false));
        let again = PlayedWithBook::open(&dir, &me.public_key(), APP);
        assert_eq!(again.list().len(), 1);
        assert_eq!(again.list()[0].name, "B");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn capped_at_500_dropping_the_least_recently_played() {
        let dir = temp_dir("cap");
        let (book, _) = open(&dir);
        let first = Guest::new();
        book.record(
            &first.attestation(NOW),
            &first.runtime.public_key(),
            "oldest",
            &[],
            NOW,
        )
        .unwrap();
        let mut keep: Vec<Guest> = Vec::new();
        for i in 1..MAX_ENTRIES {
            let g = Guest::new();
            book.record(
                &g.attestation(NOW),
                &g.runtime.public_key(),
                "g",
                &[],
                NOW + i as u64,
            )
            .unwrap();
            keep.push(g);
        }
        assert_eq!(book.len(), MAX_ENTRIES);
        assert!(book.by_persona(&first.persona.public_key()).is_some());
        // The 501st pushes out the oldest.
        let extra = Guest::new();
        book.record(
            &extra.attestation(NOW),
            &extra.runtime.public_key(),
            "new",
            &[],
            NOW + 9_999,
        )
        .unwrap();
        assert_eq!(book.len(), MAX_ENTRIES);
        assert!(book.by_persona(&first.persona.public_key()).is_none());
        assert!(book.by_persona(&extra.persona.public_key()).is_some());
        assert!(book.by_persona(&keep[0].persona.public_key()).is_some());
        // Playing with someone again protects them: the next drop is another.
        book.record(
            &keep[0].attestation(NOW),
            &keep[0].runtime.public_key(),
            "g",
            &[],
            NOW + 10_000,
        )
        .unwrap();
        let extra2 = Guest::new();
        book.record(
            &extra2.attestation(NOW),
            &extra2.runtime.public_key(),
            "new2",
            &[],
            NOW + 10_001,
        )
        .unwrap();
        assert!(book.by_persona(&keep[0].persona.public_key()).is_some());
        assert!(book.by_persona(&keep[1].persona.public_key()).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn relays_are_validated_and_trimmed_to_three() {
        let dir = temp_dir("relays");
        let (book, _) = open(&dir);
        let g = Guest::new();
        let long = format!("wss://{}.test", "a".repeat(260));
        let mixed = vec![
            "ws://insecure.test".to_string(),
            "https://not-a-relay.test".to_string(),
            "wss://good1.test".to_string(),
            long,
            "wss://user:pw@creds.test".to_string(),
            "wss://white space.test".to_string(),
            "wss://good1.test/".to_string(),
            "wss://good2.test".to_string(),
            "wss://good3.test".to_string(),
            "wss://good4.test".to_string(),
        ];
        let e = book
            .record(
                &g.attestation(NOW),
                &g.runtime.public_key(),
                "G",
                &mixed,
                NOW,
            )
            .unwrap();
        assert_eq!(
            e.inbox_relays,
            ["wss://good1.test", "wss://good2.test", "wss://good3.test"]
        );
        assert!(valid_inbox_relay("wss://relay.damus.io"));
        assert!(valid_inbox_relay("wss://relay.test:7777/path"));
        assert!(!valid_inbox_relay(""));
        assert!(!valid_inbox_relay("wss://"));
        let max = format!("wss://{}", "a".repeat(MAX_RELAY_URL - 6));
        assert!(valid_inbox_relay(&max) && !valid_inbox_relay(&format!("{max}a")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn names_are_sanitised() {
        let dir = temp_dir("names");
        let (book, _) = open(&dir);
        let g = Guest::new();
        let e = book
            .record(
                &g.attestation(NOW),
                &g.runtime.public_key(),
                "  Al\u{202e}ex\n",
                &[],
                NOW,
            )
            .unwrap();
        assert_eq!(e.name, "Alex");
        let long = "x".repeat(200);
        let e = book
            .record(
                &g.attestation(NOW),
                &g.runtime.public_key(),
                &long,
                &[],
                NOW + 1,
            )
            .unwrap();
        assert_eq!(e.name.chars().count(), MAX_NAME);
        assert_eq!(book.set_name(&g.persona.public_key(), "Zed"), Ok(true));
        assert_eq!(book.set_name(&g.persona.public_key(), "Zed"), Ok(false));
        assert_eq!(
            book.set_name(&Keys::generate().public_key(), "Nobody"),
            Ok(false)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rekey_swaps_the_key_without_counting_a_game() {
        let dir = temp_dir("rekey");
        let (book, _) = open(&dir);
        let g = Guest::new();
        book.record(
            &g.attestation(NOW),
            &g.runtime.public_key(),
            "G",
            &relays(1),
            NOW,
        )
        .unwrap();
        let g2 = g.rekeyed();
        let e = book
            .rekey(
                &g.persona.public_key(),
                &g2.runtime.public_key(),
                &g2.attestation(NOW + 5),
                NOW + 5,
            )
            .unwrap();
        assert_eq!((e.games, e.last_played, e.name.as_str()), (1, NOW, "G"));
        assert_eq!(e.runtime, g2.runtime.public_key().to_hex());
        // A different persona's attestation cannot take the entry.
        let thief = Guest::new();
        assert!(
            book.rekey(
                &g.persona.public_key(),
                &thief.runtime.public_key(),
                &thief.attestation(NOW),
                NOW
            )
            .is_err()
        );
        assert_eq!(
            book.by_persona(&g.persona.public_key()).unwrap().runtime,
            g2.runtime.public_key().to_hex()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_different_key_needs_a_strictly_newer_attestation() {
        let dir = temp_dir("stale");
        let (book, _) = open(&dir);
        let g = Guest::new();
        book.record(&g.attestation(NOW), &g.runtime.public_key(), "G", &[], NOW)
            .unwrap();
        let old = g.rekeyed();
        // Same instant: not newer. Older: not newer. Both refused, by record and rekey.
        for at in [NOW, NOW - 100] {
            let att = old.attestation(at);
            let stale = Err(BookError::BadAttestation(STALE_ATTESTATION));
            assert_eq!(
                book.record(&att, &old.runtime.public_key(), "G", &[], NOW + 1)
                    .map(|_| ()),
                stale
            );
            assert_eq!(
                book.rekey(
                    &g.persona.public_key(),
                    &old.runtime.public_key(),
                    &att,
                    NOW + 1
                )
                .map(|_| ()),
                stale
            );
        }
        let held = book.by_persona(&g.persona.public_key()).unwrap();
        assert_eq!(
            (held.runtime.as_str(), held.games),
            (g.runtime.public_key().to_hex().as_str(), 1)
        );
        // A newer one is taken.
        let newer = g.rekeyed();
        book.record(
            &newer.attestation(NOW + 1),
            &newer.runtime.public_key(),
            "G",
            &[],
            NOW + 1,
        )
        .unwrap();
        let held = book.by_persona(&g.persona.public_key()).unwrap();
        assert_eq!(
            (held.runtime, held.games),
            (newer.runtime.public_key().to_hex(), 2)
        );
        // The same key with an older attestation counts the game but keeps the newer one.
        let held_att = held.attestation.clone();
        book.record(
            &newer.attestation(NOW - 5),
            &newer.runtime.public_key(),
            "G",
            &[],
            NOW + 2,
        )
        .unwrap();
        let held = book.by_persona(&g.persona.public_key()).unwrap();
        assert_eq!((held.games, held.attestation), (3, held_att));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn one_runtime_key_belongs_to_one_persona() {
        let dir = temp_dir("dup-runtime");
        let (book, _) = open(&dir);
        let (a, b) = (Guest::new(), Guest::new());
        book.record(&a.attestation(NOW), &a.runtime.public_key(), "A", &[], NOW)
            .unwrap();
        // Persona B signs an attestation for A's runtime key.
        let forged = Guest {
            persona: b.persona.clone(),
            runtime: a.runtime.clone(),
        };
        assert!(
            book.record(
                &forged.attestation(NOW),
                &forged.runtime.public_key(),
                "B",
                &[],
                NOW
            )
            .is_err()
        );
        assert!(book.by_persona(&b.persona.public_key()).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn relays_on_the_local_network_are_not_inbox_relays() {
        for bad in [
            "wss://localhost/",
            "wss://relay.local/",
            "wss://127.0.0.1:7777",
            "wss://192.168.1.1/",
            "wss://10.0.0.5",
            "wss://169.254.1.1",
            "wss://[::1]/",
            "wss://[fe80::1]/",
            "wss://[fd00::1]/",
        ] {
            assert!(!valid_inbox_relay(bad), "{bad}");
        }
        assert!(valid_inbox_relay("wss://relay.example.com"));
        assert!(valid_inbox_relay("wss://8.8.8.8/"));
    }

    #[test]
    fn a_newer_file_format_is_set_aside_not_overwritten() {
        let dir = temp_dir("future");
        let me = Keys::generate();
        let book = PlayedWithBook::open(&dir, &me.public_key(), APP);
        let g = Guest::new();
        book.record(&g.attestation(NOW), &g.runtime.public_key(), "G", &[], NOW)
            .unwrap();
        let file = file_name(&me.public_key());
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(&file)).unwrap()).unwrap();
        v["v"] = serde_json::json!(99);
        std::fs::write(dir.join(&file), v.to_string()).unwrap();
        let again = PlayedWithBook::open(&dir, &me.public_key(), APP);
        assert!(again.is_empty());
        let asides = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .count();
        assert_eq!(asides, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn saved_atomically_in_a_private_file_and_reloaded() {
        let dir = temp_dir("atomic");
        let (book, me) = open(&dir);
        let g = Guest::new();
        book.record(
            &g.attestation(NOW),
            &g.runtime.public_key(),
            "G",
            &relays(1),
            NOW,
        )
        .unwrap();
        let file = dir.join(file_name(&me.public_key()));
        assert!(file.exists());
        assert!(
            !dir.join(format!("{}.tmp", file_name(&me.public_key())))
                .exists(),
            "the temp file was renamed away"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // The file name does not carry the persona key.
        assert!(!file.to_string_lossy().contains(&me.public_key().to_hex()));
        assert_eq!(book.on_disk().unwrap(), book.list());
        // A stray temp file from a crashed save does not matter.
        std::fs::write(
            dir.join(format!("{}.tmp", file_name(&me.public_key()))),
            b"{torn",
        )
        .unwrap();
        let again = PlayedWithBook::open(&dir, &me.public_key(), APP);
        assert_eq!(again.list(), book.list());
        // Another persona's book in the same directory is separate.
        let other = Keys::generate();
        assert!(PlayedWithBook::open(&dir, &other.public_key(), APP).is_empty());
        // A damaged file is copied aside, kept in place, and the book starts empty.
        std::fs::write(&file, b"{torn").unwrap();
        let broken = PlayedWithBook::open(&dir, &me.public_key(), APP);
        assert!(broken.is_empty());
        assert_eq!(std::fs::read(&file).unwrap(), b"{torn", "not deleted");
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_save_changes_nothing() {
        let dir = temp_dir("failsave");
        let (book, _) = open(&dir);
        let g = Guest::new();
        book.record(&g.attestation(NOW), &g.runtime.public_key(), "G", &[], NOW)
            .unwrap();
        // Make the directory unwritable by replacing it with a file.
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, b"not a directory").unwrap();
        let h = Guest::new();
        assert!(matches!(
            book.record(&h.attestation(NOW), &h.runtime.public_key(), "H", &[], NOW),
            Err(BookError::Save(_))
        ));
        assert_eq!(book.len(), 1);
        assert!(matches!(
            book.forget(&g.persona.public_key()),
            Err(BookError::Save(_))
        ));
        assert_eq!(book.len(), 1);
        let _ = std::fs::remove_file(dir);
    }
}
