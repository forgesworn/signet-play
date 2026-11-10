//! Small JSON files under `data_dir/signet/`, written atomically with mode
//! 0600 (temp file, fsync, rename, fsync of the directory).
//!
//! A file that does not parse is **never renamed away**: its bytes are first
//! copied to `<name>.corrupt-<unix>` (the newest [`CORRUPT_KEEP`] kept) and
//! fsynced, and only then is the original replaced. Two kinds of caller:
//!
//! - [`Store::load`] is for files whose absence is the safe state (a session,
//!   a cached copy): after the copy the damaged original is removed and the
//!   file reads as absent.
//! - [`Store::load_keep`] is for files that remember a "no" or a debt (the
//!   used runtime keys, the old public notes, the played-with book). The
//!   damaged original stays where it is until the caller atomically rewrites
//!   it with the fail-closed content, so a crash at any point leaves either
//!   the original or the rewrite, never a missing file.
//!
//! A file that cannot be read at all (an I/O error), or whose copy could not
//! be written, cannot be copied: it is **never deleted** either. It is set
//! aside whole under `<name>.bad` (then `<name>.bad-2`, ... up to
//! [`CORRUPT_KEEP`], never overwriting one): [`Store::load`] moves it there,
//! [`Store::load_keep`] gives it that second name and leaves it in place.
//! When neither works, it stays where it is.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

pub(crate) const SESSION: &str = "session.json";
/// `signin.json`: what Sign in with Signet learned (see [`SignInRecord`]).
pub(crate) const SIGNIN: &str = "signin.json";
pub(crate) const ATTESTATION: &str = "attestation.json";
pub(crate) const PROFILE: &str = "profile.json";
pub(crate) const GRANT: &str = "contacts-grant.json";
pub(crate) const SNAPSHOT: &str = "contacts.json";
/// Blocks kept after the contacts grant went away.
pub(crate) const KEPT_BLOCKS: &str = "kept-blocks.json";
/// Hashes of the runtime keys a sign-in used, and of those retired at sign-out.
pub(crate) const RUNTIME_KEYS: &str = "runtime-keys.json";
/// Event ids of notes an earlier version published (see `crate::legacy`).
pub(crate) const OLD_PUBLIC_NOTES: &str = "old-public-notes.json";

/// Friend links, outgoing pending links and handled hello ids (see `signet::friend`).
pub(crate) const FRIEND_LINKS: &str = "friend-links.json";

/// How many used runtime keys are remembered.
pub(crate) const USED_KEEP: usize = 1024;
/// How many retired runtime keys are remembered.
pub(crate) const RETIRED_KEEP: usize = 32;

/// `signin.json`: the persona that signed in with Signet, the handle it shared
/// (if any), and whether a NIP-46 signer (`session.json`) stands behind it.
/// Without a signer this file is the whole sign-in.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub(crate) struct SignInRecord {
    pub persona: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub signer: bool,
}

/// `runtime-keys.json`: SHA-256 hashes (hex) of the runtime keys a sign-in on
/// this device has used, and of those retired at sign-out. A runtime key is
/// public to everyone you play with, so the hash only keeps the file from
/// reading as a list of keys.
#[derive(Clone, Debug, Default, Serialize, serde::Deserialize)]
pub(crate) struct RuntimeKeys {
    pub used: Vec<String>,
    pub retired: Vec<String>,
}

impl RuntimeKeys {
    pub fn add_used(&mut self, hash: String) {
        if !self.used.contains(&hash) {
            self.used.push(hash);
        }
        let skip = self.used.len().saturating_sub(USED_KEEP);
        self.used.drain(..skip);
    }

    pub fn add_retired(&mut self, hash: String) {
        if !self.retired.contains(&hash) {
            self.retired.push(hash);
        }
        let skip = self.retired.len().saturating_sub(RETIRED_KEEP);
        self.retired.drain(..skip);
    }
}

/// The hash a runtime key is remembered by.
pub(crate) fn runtime_hash(runtime: &nostr::PublicKey) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"runtime-key");
    h.update(runtime.to_bytes());
    hex::encode(h.finalize())
}

/// How many `<name>.corrupt-<unix>` copies are kept per file.
pub(crate) const CORRUPT_KEEP: usize = 3;

/// Largest file we read back.
const MAX_FILE: u64 = 4 * 1024 * 1024;

/// What reading a file found, before the caller decides what to do with it.
enum Read<T> {
    Ok(T),
    Absent,
    /// Does not parse; whether its bytes are safe in an aside copy.
    Unparsed(bool),
    /// Could not be read at all: nothing could be copied.
    Unreadable,
}

/// What [`Store::load_keep`] found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Loaded<T> {
    Ok(T),
    /// No such file.
    Absent,
    /// There, but it does not parse (or cannot be read). A copy is kept aside
    /// and the file itself is still in place.
    Damaged,
}

#[derive(Clone, Debug)]
pub(crate) struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(data_dir: &Path) -> Store {
        Store {
            dir: data_dir.join("signet"),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A store directly in `dir` (the played-with book's directory).
    pub fn in_dir(dir: &Path) -> Store {
        Store {
            dir: dir.to_path_buf(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Read `name`. A file that does not parse is copied aside and removed,
    /// and reads as absent (see the module docs).
    pub fn load<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        match self.read(name) {
            Read::Ok(v) => Some(v),
            Read::Absent => None,
            Read::Unparsed(true) => {
                // The bytes are safe in the aside copy; absence is this
                // file's safe state.
                self.remove(name);
                None
            }
            // Nothing could be copied: the file is moved aside whole.
            Read::Unparsed(false) | Read::Unreadable => {
                self.keep_bad(name, false);
                None
            }
        }
    }

    /// Read `name`. A damaged file is copied aside (fsynced) but **left in
    /// place**: the caller must rewrite it at once with the fail-closed
    /// content ([`Store::save`] replaces it atomically).
    pub fn load_keep<T: DeserializeOwned>(&self, name: &str) -> Loaded<T> {
        match self.read(name) {
            Read::Ok(v) => Loaded::Ok(v),
            Read::Absent => Loaded::Absent,
            Read::Unparsed(true) => Loaded::Damaged,
            // Nothing could be copied: a second name keeps the bytes when the
            // caller's rewrite replaces this one.
            Read::Unparsed(false) | Read::Unreadable => {
                self.keep_bad(name, true);
                Loaded::Damaged
            }
        }
    }

    fn read<T: DeserializeOwned>(&self, name: &str) -> Read<T> {
        let path = self.path(name);
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Read::Absent,
            // Present but not even inspectable: damaged, and nothing to copy.
            Err(_) => return Read::Unreadable,
        };
        if meta.len() > MAX_FILE {
            log::warn!("[signet] {name} is too large to read; keeping a copy aside");
            return Read::Unparsed(self.set_aside(name));
        }
        let Ok(bytes) = std::fs::read(&path) else {
            return Read::Unreadable;
        };
        match serde_json::from_slice(&bytes) {
            Ok(v) => Read::Ok(v),
            Err(e) => {
                // Where, not what: the error text can quote the file.
                log::warn!(
                    "[signet] {name} is unreadable ({:?} error at line {}); keeping a copy aside",
                    e.classify(),
                    e.line()
                );
                Read::Unparsed(self.set_aside(name))
            }
        }
    }

    /// Give a file that could not be copied the first free `<name>.bad`
    /// name: by a move (`keep` false), or by a second link that leaves it in
    /// place (`keep` true). Never overwrites, never deletes; one log line.
    fn keep_bad(&self, name: &str, keep: bool) {
        let from = self.path(name);
        for n in 1..=CORRUPT_KEEP {
            let bad = if n == 1 { format!("{name}.bad") } else { format!("{name}.bad-{n}") };
            let to = self.path(&bad);
            if std::fs::symlink_metadata(&to).is_ok() {
                continue;
            }
            let done = if keep {
                std::fs::hard_link(&from, &to)
            } else {
                std::fs::rename(&from, &to)
            };
            match done {
                Ok(()) => {
                    log::warn!("[signet] {name} could not be read; set aside as {bad}");
                    self.sync_dir();
                }
                Err(e) => log::warn!("[signet] {name} could not be read, nor set aside: {}", e.kind()),
            }
            return;
        }
        log::warn!("[signet] {name} could not be read; left in place (no free .bad name)");
    }

    /// Whether the file is there (readable or not).
    pub fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    /// Copy `name` to `<name>.corrupt-<unix>` and fsync it, keeping the newest
    /// [`CORRUPT_KEEP`] copies. The original is not touched. A file that is
    /// already kept aside byte for byte (a damaged file read again, launch
    /// after launch) is not copied again, so the first copy is not pushed out.
    /// Returns whether a copy of the bytes is now aside.
    pub fn set_aside(&self, name: &str) -> bool {
        let Ok(bytes) = std::fs::read(self.path(name)) else {
            return false;
        };
        let mut kept = self
            .aside_copies(name)
            .iter()
            .any(|p| std::fs::read(p).is_ok_and(|b| b == bytes));
        if !kept {
            let aside = format!("{name}.corrupt-{}", crate::unix_now());
            match write_0600(&self.path(&aside), &bytes) {
                Ok(()) => kept = true,
                Err(e) => log::warn!("[signet] could not keep a copy of {name} aside: {e}"),
            }
        }
        let prefix = format!("{name}.corrupt-");
        let mut copies: Vec<(u64, PathBuf)> = self
            .aside_copies(name)
            .into_iter()
            .map(|p| {
                let stamp = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_prefix(&prefix))
                    .unwrap_or("");
                (stamp.parse().unwrap_or(0), p)
            })
            .collect();
        copies.sort();
        let excess = copies.len().saturating_sub(CORRUPT_KEEP);
        for (_, p) in copies.into_iter().take(excess) {
            let _ = std::fs::remove_file(p);
        }
        self.sync_dir();
        kept
    }

    /// The `<name>.corrupt-*` copies on disk.
    pub fn aside_copies(&self, name: &str) -> Vec<PathBuf> {
        let prefix = format!("{name}.corrupt-");
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        rd.flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(&prefix))
            })
            .map(|e| e.path())
            .collect()
    }

    /// Every file name in the directory that starts with `prefix` and ends
    /// with `.json`, sorted (aside copies and temp files excluded).
    pub fn files_with_prefix(&self, prefix: &str) -> Vec<String> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut out: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(prefix) && n.ends_with(".json"))
            .collect();
        out.sort();
        out
    }

    /// Remove `name` and every copy of it: the `<name>.corrupt-*` copies, the
    /// `<name>.bad*` files set aside, and a `<name>.tmp` left by a crashed save.
    pub fn remove_with_asides(&self, name: &str) {
        self.remove(name);
        let bad = format!("{name}.bad");
        let mut sides = self.aside_copies(name);
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            sides.extend(
                rd.flatten()
                    .filter(|e| {
                        e.file_name().to_str().is_some_and(|n| {
                            n == bad || n.strip_prefix(&bad).is_some_and(|r| r.starts_with('-'))
                        })
                    })
                    .map(|e| e.path()),
            );
        }
        sides.push(self.path(&format!("{name}.tmp")));
        for p in sides {
            let _ = std::fs::remove_file(p);
        }
        self.sync_dir();
    }

    /// Flush the directory entry changes (a rename or a removal) to disk, so
    /// a power loss cannot bring a removed file back or undo a new one.
    fn sync_dir(&self) {
        #[cfg(unix)]
        if let Ok(d) = std::fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }
    }

    pub fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<(), String> {
        create_private_dir(&self.dir)?;
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
        let tmp = self.path(&format!("{name}.tmp"));
        write_0600(&tmp, &bytes)?;
        std::fs::rename(&tmp, self.path(name))
            .map_err(|e| format!("could not save {name}: {e}"))?;
        self.sync_dir();
        Ok(())
    }

    pub fn remove(&self, name: &str) {
        let _ = std::fs::remove_file(self.path(name));
        self.sync_dir();
    }
}

fn create_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    // `mode` applies only when the file is created; a leftover tmp file keeps
    // whatever it had.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    }
    f.write_all(bytes)
        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
    f.sync_all()
        .map_err(|e| format!("could not write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn temp_dir(tag: &str) -> PathBuf {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        std::env::temp_dir().join(format!("decented-signet-{tag}-{}", hex::encode(b)))
    }

    #[test]
    fn round_trip_mode_and_corruption() {
        let dir = temp_dir("store");
        let s = Store::new(&dir);
        assert_eq!(s.load::<Vec<u32>>("x.json"), None);
        s.save("x.json", &vec![1u32, 2]).unwrap();
        assert_eq!(s.load::<Vec<u32>>("x.json"), Some(vec![1, 2]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("signet/x.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(dir.join("signet/x.json"), b"{nope").unwrap();
        assert_eq!(s.load::<Vec<u32>>("x.json"), None);
        assert!(!dir.join("signet/x.json").exists());
        assert_eq!(s.aside_copies("x.json").len(), 1);
        assert_eq!(
            std::fs::read(&s.aside_copies("x.json")[0]).unwrap(),
            b"{nope",
            "the bytes are kept"
        );
        // Only the newest CORRUPT_KEEP copies are kept.
        for stamp in 1..=5 {
            std::fs::write(dir.join(format!("signet/x.json.corrupt-{stamp}")), b"old").unwrap();
        }
        std::fs::write(dir.join("signet/x.json"), b"{nope").unwrap();
        assert_eq!(s.load::<Vec<u32>>("x.json"), None);
        assert_eq!(s.aside_copies("x.json").len(), CORRUPT_KEEP);
        assert!(
            !dir.join("signet/x.json.corrupt-1").exists()
                && !dir.join("signet/x.json.corrupt-2").exists()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_kept_file_stays_until_rewritten_and_a_copy_is_made_once() {
        let dir = temp_dir("store-keep");
        let s = Store::new(&dir);
        assert_eq!(s.load_keep::<Vec<u32>>("k.json"), Loaded::Absent);
        std::fs::create_dir_all(dir.join("signet")).unwrap();
        std::fs::write(dir.join("signet/k.json"), b"{torn").unwrap();
        for _ in 0..3 {
            assert_eq!(s.load_keep::<Vec<u32>>("k.json"), Loaded::Damaged);
            assert_eq!(
                std::fs::read(dir.join("signet/k.json")).unwrap(),
                b"{torn",
                "never renamed away"
            );
        }
        assert_eq!(
            s.aside_copies("k.json").len(),
            1,
            "the same bytes are kept aside once"
        );
        s.save("k.json", &vec![7u32]).unwrap();
        assert_eq!(s.load_keep::<Vec<u32>>("k.json"), Loaded::Ok(vec![7]));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Make `path` unreadable; `false` if it still reads (root reads anything).
    #[cfg(unix)]
    fn unreadable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::read(path).is_err()
    }

    #[cfg(unix)]
    fn read_back(path: &Path) -> Vec<u32> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_cannot_be_read_is_set_aside_never_deleted() {
        let dir = temp_dir("store-bad");
        let s = Store::new(&dir);
        let sd = dir.join("signet");
        s.save("x.json", &vec![1u32]).unwrap();
        if !unreadable(&sd.join("x.json")) {
            // Running as root: nothing here is tested (shown with --nocapture).
            eprintln!("skipped: a file at mode 000 still reads (root), so nothing is unreadable");
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        assert_eq!(s.load::<Vec<u32>>("x.json"), None);
        assert!(!sd.join("x.json").exists(), "reads as absent");
        // A second one does not overwrite the first.
        s.save("x.json", &vec![2u32]).unwrap();
        assert!(unreadable(&sd.join("x.json")));
        assert_eq!(s.load::<Vec<u32>>("x.json"), None);
        assert_eq!(read_back(&sd.join("x.json.bad")), vec![1]);
        assert_eq!(read_back(&sd.join("x.json.bad-2")), vec![2]);

        // A file kept in place gets a second name that outlives its rewrite.
        s.save("k.json", &vec![3u32]).unwrap();
        assert!(unreadable(&sd.join("k.json")));
        assert_eq!(s.load_keep::<Vec<u32>>("k.json"), Loaded::Damaged);
        assert!(sd.join("k.json").exists(), "left in place");
        s.save("k.json", &vec![4u32]).unwrap();
        assert_eq!(read_back(&sd.join("k.json.bad")), vec![3]);
        assert_eq!(s.load_keep::<Vec<u32>>("k.json"), Loaded::Ok(vec![4]));
        let _ = std::fs::remove_dir_all(dir);
    }
}
