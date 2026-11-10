//! The [`Signet`] handle: state, persistence and the background flows.
//!
//! Private play never publishes a persona-to-game link (kit rules
//! 1, 2, 5, 7); explicit public result sharing is isolated in [`sharing`].
//! The attestation is kept on the phone; people
//! are reached through the played-with book; and the connections are kept
//! apart by purpose:
//!
//! - the **persona connection** (`Inner::persona_relay`): NIP-46 sign-in, the
//!   persona's kind 0 (one lookup at a time);
//! - a connection per contacts-projection read and per NIP-46 restore;
//! - the invite inbox's **own** connection, opened by [`Signet::inbox`], which
//!   carries the runtime key and never a persona;
//! - a fresh connection for each invite sent, and each retraction relay.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

use nostr::{Event, EventId, Filter, Keys, Kind, PublicKey};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch};
use tokio::task::AbortHandle;

mod friend;
pub mod permission;
pub mod signin;
pub mod sharing;

pub use friend::{
    FRIEND_REPLY_RUMOR_KIND, FriendEvent, FriendHello, LiveFriendLink, MAX_HELLOS_PER_LINK,
    MAX_HELLOS_PER_SENDER, MAX_LIVE_LINKS, MAX_PENDING, PendingFriendLink,
};

use crate::attestation::{PersonaInfo, unsigned_attestation, verify_attestation_event};
use crate::contacts::{
    self, Accepted, AckNext, Contact, ContactBook, ContactsSync, Grant, PairingLinks,
    SNAPSHOT_VERSION, Snapshot,
};
use crate::contacts_wire::pairing::is_valid_contacts_relay_url;
use crate::contacts_wire::sanitize_wire_text;
use crate::invite::{self, Invite, InviteError, InvitePayload};
use crate::legacy::{self, OldNotes};
use crate::nip46::{self, PendingPair, PersistedSession, RemoteSigner};
use crate::played_with::{PlayedWithBook, PlayedWithEntry, clean_inbox_relays};
use crate::relay::{Connector, Relay, RelayMsg, Subscription, WsConnector, fetch};
use crate::store::{self, Loaded, RuntimeKeys, SignInRecord, Store, runtime_hash};
use crate::{Task, runtime, unix_now};

/// Same defaults as the transport.
pub use decented_relays::{DEFAULT_RELAYS, normalize_relay_url};
/// Private-play permissions advertised in the `nostrconnect://` URI:
/// the attestation (kind 30420) and the NIP-09 retraction of old public notes.
pub const NIP46_PERMS: &str = "sign_event:30420,sign_event:5";
/// Longest persona name kept from a kind 0.
pub const MAX_PROFILE_NAME: usize = 64;
/// Folder of the played-with books, inside the crate's data folder.
const BOOK_DIR: &str = "played-with";

/// What the crate needs to know about the game. The crate names no game: the
/// app id, the name My Signet shows, and the sign-in callback all come from
/// here.
#[derive(Clone, Debug)]
pub struct SignetConfig {
    pub data_dir: PathBuf,
    /// The player's relays, in their order: NIP-46, kind 0 names, the
    /// invite inbox and retractions.
    pub relays: Vec<String>,
    /// The attestation's `d` tag: which game a persona-to-runtime link is for.
    /// Never published.
    pub app_id: String,
    /// Shown by My Signet on the approval and grant screens.
    pub app_name: String,
    /// `callback=` on the My Signet App Link (`None` = omit). My Signet drops
    /// non-https callbacks (see [`crate::mysignet_app_link`]).
    pub signin_callback: Option<String>,
    /// The `origin` of Sign in with Signet ([`Signet::sign_in_with_signet`]): a
    /// bare `https://host`, compared as a string with the `origin` tag My
    /// Signet signs. Nothing needs to be hosted there. `None` turns that
    /// sign-in off.
    pub signin_origin: Option<String>,
    /// Where Sign in with Signet tries first, in order (e.g. a relay My Signet
    /// itself uses, then reliable public ones). The kit names none; the app
    /// supplies them. The player's own [`SignetConfig::relays`] follow, minus
    /// repeats ([`signin::relay_order`]). Empty: just the player's relays.
    pub signin_relays: Vec<String>,
    /// How long one candidate relay gets to confirm the sign-in subscription
    /// before the next is tried ([`signin::OPEN_WAIT`]).
    pub signin_open_wait: Duration,
    /// How long sign-in waits for the person to approve in My Signet.
    pub pairing_timeout: Duration,
    /// The reason My Signet shows (labelled "The app says:") when
    /// [`Signet::ask_online_permission`] asks for online play: 1-200
    /// characters, refused (never cut) when longer. `None` turns that ask off.
    /// The name shown with it is `app_name`.
    pub permission_reason: Option<String>,
    /// How long [`Signet::ask_online_permission`] waits for an answer
    /// ([`permission::PERMISSION_WAIT_SECS`]).
    pub permission_wait: Duration,
    /// How long one NIP-46 request (e.g. signing the attestation) may take.
    pub request_timeout: Duration,
    /// How long a relay fetch waits for EOSE.
    pub fetch_timeout: Duration,
    /// How long contacts pairing waits for My Signet's ack.
    pub ack_timeout: Duration,
    /// While an [`InviteInbox`] is open, re-read the contacts projection this
    /// often (so a block made in My Signet takes effect without the app asking).
    pub contacts_refresh: Duration,
}

impl SignetConfig {
    pub fn new(
        data_dir: impl Into<PathBuf>,
        app_id: impl Into<String>,
        app_name: impl Into<String>,
        signin_callback: Option<String>,
    ) -> Self {
        SignetConfig {
            data_dir: data_dir.into(),
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            app_id: app_id.into(),
            app_name: app_name.into(),
            signin_callback,
            signin_origin: None,
            signin_relays: Vec::new(),
            signin_open_wait: signin::OPEN_WAIT,
            pairing_timeout: Duration::from_secs(180),
            permission_reason: None,
            permission_wait: Duration::from_secs(permission::PERMISSION_WAIT_SECS),
            request_timeout: Duration::from_secs(120),
            fetch_timeout: Duration::from_secs(8),
            ack_timeout: Duration::from_secs(600),
            contacts_refresh: Duration::from_secs(5 * 60),
        }
    }
}

/// Why [`Signet::sign_in`] will not start (see [`Signet::sign_in_refusal`]).
/// The sign-in's `Failed` event carries the matching sentence; the app
/// replaces its runtime key and opens a new [`Signet`] on the new key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInRefusal {
    /// This runtime key was retired at sign-out.
    KeyRetired,
    /// A sign-in on this device already used this runtime key (it is signed
    /// in with it now, or was, or its session was lost). Every sign-in needs
    /// a new runtime key, so a key never carries two personas.
    KeyAlreadyUsed,
}

/// What [`Signet::sign_out`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignOutOutcome {
    /// `true` whenever the sign-out happened: this runtime key is retired.
    /// The app must replace its runtime key / `Identity` and open a new
    /// [`Signet`] on the new key before the next sign-in (this one refuses to
    /// sign in again).
    pub rotate_runtime_key: bool,
    /// Whether anyone was signed in to sign out.
    pub signed_out: bool,
    /// How many live friend links the sign-out ended (their mailbox keys
    /// were for this install's runtime key, which is retired). Say so when it
    /// is not zero.
    pub friend_links_dropped: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedProfile {
    persona: String,
    name: Option<String>,
    fetched_at: u64,
}

/// `kept-blocks.json`: blocks that outlive a revoked / forgotten grant.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct KeptBlocks {
    persona: String,
    blocked: Vec<String>,
}

struct State {
    session: Option<PersistedSession>,
    persona: Option<PublicKey>,
    attestation: Option<(Event, PersonaInfo)>,
    profile: Option<CachedProfile>,
    grant: Option<Grant>,
    snapshot: Option<Snapshot>,
    /// Blocks kept after the grant went away (this persona only).
    kept_blocks: Vec<PublicKey>,
    /// This runtime key was retired at sign-out.
    retired: bool,
    /// A sign-in on this device has already used this runtime key.
    used: bool,
    /// A signer already talking to My Signet in this process.
    signer: Option<Arc<RemoteSigner>>,
    sharing_signers: HashMap<sharing::SharingScope, (PersistedSession, Arc<RemoteSigner>)>,
    sign_in_gen: u64,
    /// Bumped by each [`Signet::ask_online_permission`]: only the newest ask
    /// may store its answer.
    permission_gen: u64,
    /// The persona's handle as My Signet shared it at sign-in (cleaned, at most
    /// 64 characters); `None` when the person did not share one.
    shared_name: Option<String>,
    /// The persona's played-with book.
    book: Option<PlayedWithBook>,
    /// `old-public-notes.json`, as read at launch or written since.
    old_notes: OldNotes,
    /// Friend links: live, pending, waiting hellos (`friend.rs`).
    friends: friend::FriendState,
}

impl State {
    /// A persona is signed in (with a NIP-46 signer, or by Sign in with Signet
    /// without one).
    fn signed_in(&self) -> bool {
        self.persona.is_some()
    }

    /// On a live key, and able to be attested: a signer is behind the
    /// sign-in (it can mint one), or a stored attestation is still valid (a
    /// persona signed in without a bunker, approved by My Signet). Neither
    /// path uses the persona's NIP-46 signer: invites and friend links seal
    /// with the runtime key and carry the attestation.
    fn accepting_invites(&self) -> bool {
        self.accepting_invites_at(unix_now())
    }

    fn accepting_invites_at(&self, now: u64) -> bool {
        if self.retired {
            return false;
        }
        self.session.is_some()
            || self
                .attestation
                .as_ref()
                .is_some_and(|(_, i)| now <= i.valid_until)
    }

    /// A grant exists and its book is missing or past `expiresAt`.
    fn contacts_stale(&self, now: u64) -> bool {
        self.grant.is_some()
            && self
                .snapshot
                .as_ref()
                .is_none_or(|s| ContactBook::from_snapshot(s).is_stale(now))
    }
}

struct Inner {
    cfg: SignetConfig,
    runtime_keys: Keys,
    connector: Arc<dyn Connector>,
    /// The **persona connection**: NIP-46 sign-in and the *signed-in
    /// persona's own* kind 0. Never used for the runtime-key inbox, for
    /// sending invites, or for looking up anybody else's name (each of those
    /// gets a connection of its own).
    persona_relay: Arc<dyn Relay>,
    store: Store,
    state: Mutex<State>,
    /// Bumped whenever the receive policy may have changed (contacts
    /// refreshed, signed out): open inboxes re-check.
    policy: watch::Sender<u64>,
    /// Kind 0 lookups run one at a time, never in a batch.
    lookup: tokio::sync::Mutex<()>,
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn policy_changed(&self) {
        self.policy.send_modify(|g| *g = g.wrapping_add(1));
    }
}

/// The My Signet integration for one install. Cheap to clone.
#[derive(Clone)]
pub struct Signet {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Signet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signet")
            .field("persona", &self.persona())
            .finish()
    }
}

const RETIRED_KEY: &str =
    "This install's key was retired at sign-out. Restart with a new install key to sign in.";
/// The `Failed` reason of a sign-in refused because an earlier sign-in used
/// this runtime key (see [`SignInRefusal::KeyAlreadyUsed`]).
pub const RUNTIME_KEY_USED: &str =
    "A sign-in already used this install's key. Restart with a new install key to sign in.";
const PAIRING_CONFLICT: &str =
    "Two different answers arrived for this pairing, so it isn't safe to use. Start again.";
const PAIRING_FLOOD: &str = "Too many answers arrived for this pairing. Start again.";
const NOT_SIGNED_IN_TO_RETRACT: &str = "Sign in with My Signet as the persona that published it to remove it. It may still be public until you do.";

// ─── Sign-in handle ─────────────────────────────────────────────────────────

// ─── Sign-in handle ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignInEvent {
    /// Listening on the relays: open the App Link / show the QR now, then
    /// wait for Approve in My Signet. (My Signet's reply is ephemeral; one
    /// sent before the relays carry our subscription would be lost.)
    AwaitingApproval,
    /// Paired and persisted. Signed in from here on.
    Connected {
        persona: PublicKey,
    },
    /// Asked My Signet to sign the runtime-key attestation (one more tap).
    AwaitingSignature,
    Attested {
        info: PersonaInfo,
    },
    /// Signed in, but no attestation yet; [`Signet::refresh_attestation`] retries.
    AttestationFailed {
        reason: String,
    },
    /// Sign in with Signet only: signed in by persona and name, but My Signet
    /// sent no `bunker://` (a direct-child persona gets none), so nothing can
    /// sign an attestation: no verified tick, and retrying cannot help.
    NoBunker {
        persona: PublicKey,
    },
    /// Sign-in did not happen.
    Failed {
        reason: String,
    },
}

/// One sign-in attempt. Dropping it before `Connected` cancels it.
pub struct SignIn {
    uri: String,
    /// Set once. For Sign in with Signet it is set only after a relay has
    /// confirmed the subscription (just before [`SignInEvent::AwaitingApproval`]).
    app_link: Arc<OnceLock<String>>,
    rx: Mutex<mpsc::Receiver<SignInEvent>>,
    abort: AbortHandle,
    committed: Arc<AtomicBool>,
}

impl SignIn {
    /// `nostrconnect://…`: show as a QR for another device, or paste.
    pub fn nostrconnect_uri(&self) -> &str {
        &self.uri
    }

    /// `https://mysignet.app/?nostrconnect=…&callback=…`: open on this device.
    /// For [`Signet::sign_in_with_signet`]: the `?auth=1` request link.
    ///
    /// For [`Signet::sign_in_with_signet`] it is empty until
    /// [`SignInEvent::AwaitingApproval`]: the link names the relay that
    /// opened, which is not known sooner.
    pub fn app_link(&self) -> &str {
        self.app_link.get().map(String::as_str).unwrap_or("")
    }

    /// Whether there is a `nostrconnect://` URI to show as a QR. `false` for
    /// [`Signet::sign_in_with_signet`], whose link is same-phone and single-use.
    pub fn has_qr(&self) -> bool {
        !self.uri.is_empty()
    }

    pub fn poll(&self) -> Option<SignInEvent> {
        self.rx.lock().ok()?.try_recv().ok()
    }

    /// Stop waiting. Nothing is persisted after this.
    pub fn cancel(&self) {
        self.abort.abort();
    }
}

impl Drop for SignIn {
    fn drop(&mut self) {
        // Once the session is saved the attestation mint may go on alone.
        if !self.committed.load(Ordering::SeqCst) {
            self.abort.abort();
        }
    }
}

// ─── Online-permission handle ───────────────────────────────────────────────

/// What [`Signet::ask_online_permission`] reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PermissionEvent {
    /// A relay is listening: open [`PermissionAsk::app_link`] now. For a
    /// child's persona the guardian answers on their phone, and My Signet
    /// must stay open on this one until they do.
    Waiting,
    /// My Signet signed the statement. It is stored as the attestation,
    /// exactly as a bunker-signed one is.
    Approved(PersonaInfo),
    /// Deny (the guardian) or Cancel (the person). Nothing is kept.
    Denied,
    /// No answer in [`SignetConfig::permission_wait`]. Nothing is kept; ask again.
    TimedOut,
    /// The ask did not happen, or its answer could not be kept.
    Failed { reason: String },
}

/// What a running ask shares with its [`PermissionAsk`]: the relay it
/// listens on and that subscription's status, both set once it is open.
#[derive(Default)]
struct AskLive {
    relay: OnceLock<std::sync::Weak<dyn Relay>>,
    status: OnceLock<watch::Receiver<crate::relay::SubStatus>>,
}

/// One online-play ask. Dropping it stops listening.
pub struct PermissionAsk {
    /// Set once a relay has confirmed the subscription.
    app_link: Arc<OnceLock<String>>,
    relay_host: Arc<OnceLock<String>>,
    /// The way back to the listening relay (set with the link).
    live: Arc<AskLive>,
    rx: Mutex<mpsc::Receiver<PermissionEvent>>,
    abort: AbortHandle,
}

impl PermissionAsk {
    /// The `?action=app-permission` link: empty until [`PermissionEvent::Waiting`].
    pub fn app_link(&self) -> &str {
        self.app_link.get().map(String::as_str).unwrap_or("")
    }

    /// The host of the relay the answer is awaited on (empty until `Waiting`).
    pub fn relay_host(&self) -> &str {
        self.relay_host.get().map(String::as_str).unwrap_or("")
    }

    pub fn poll(&self) -> Option<PermissionEvent> {
        self.rx.lock().ok()?.try_recv().ok()
    }

    /// Stop waiting. Nothing is stored after this.
    pub fn cancel(&self) {
        self.abort.abort();
    }

    /// Listen again on the same relay with a fresh connection, at once, with
    /// no backoff to wait out. The request, its link and its filter are the
    /// same: the answer is a stored gift wrap, so one that arrived while the
    /// phone was cut off is sent again. For when the app comes back from the
    /// background. A no-op until a relay is listening.
    pub fn reconnect(&self) {
        if let Some(relay) = self.live.relay.get().and_then(std::sync::Weak::upgrade) {
            relay.reconnect();
        }
    }

    /// The relay is being dialled now (or waits out a backoff before the
    /// next dial): asking it to reconnect would only restart the dial.
    pub fn connecting(&self) -> bool {
        self.live
            .status
            .get()
            .is_some_and(|s| matches!(*s.borrow(), crate::relay::SubStatus::Connecting))
    }

    /// The relay is connected and the subscription is out: an answer will be
    /// heard. False while reconnecting, or before a relay has opened.
    pub fn listening(&self) -> bool {
        self.live
            .status
            .get()
            .is_some_and(|s| matches!(*s.borrow(), crate::relay::SubStatus::Up))
    }
}

impl Drop for PermissionAsk {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

// ─── Contacts pairing handle ────────────────────────────────────────────────

// ─── Contacts pairing handle ────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingEvent {
    /// Links are out; waiting for the person to approve in My Signet.
    AwaitingApproval,
    /// Show this code; the person types it into My Signet and presses
    /// Continue here ([`ContactsPairing::confirm`]) only after My Signet says
    /// it matched. If My Signet says it did not match, call
    /// [`ContactsPairing::cancel`] and start a new pairing.
    VerificationCode { code: String },
    /// Grant stored; first sync done (`Unchanged` = My Signet has not
    /// published the list yet; [`Signet::refresh_contacts`] later).
    Paired { sync: ContactsSync },
    /// Nothing stored. This includes a second, different answer arriving for
    /// the same pairing (someone else answered the link too) and My Signet
    /// cancelling the grant after Continue: start a new pairing.
    Failed { reason: String },
}

/// A pairing link older than this (seconds) is rebuilt before it is opened. My
/// Signet refuses a link more than [`PAIRING_FRESHNESS_SECONDS`] old, and the
/// person may be slow to tap "Open My Signet"; 4 minutes leaves a minute to open it.
pub const PAIRING_LINK_MAX_AGE_SECS: u64 = 240;

/// True when a pairing link built at `built_at` is too old to hand to My Signet at `now`.
pub fn pairing_link_is_stale(built_at: u64, now: u64) -> bool {
    now.saturating_sub(built_at) > PAIRING_LINK_MAX_AGE_SECS
}

/// What it takes to rebuild the pairing links with a fresh timestamp.
struct LinkRecipe {
    app: PublicKey,
    app_name: String,
    relay: String,
    challenge: String,
}

/// One contacts pairing. Dropping it before Continue cancels it.
pub struct ContactsPairing {
    links: PairingLinks,
    /// Unix seconds the links were built (the `t` they carry).
    built_at: u64,
    recipe: LinkRecipe,
    rx: Mutex<mpsc::Receiver<PairingEvent>>,
    confirm: Mutex<Option<oneshot::Sender<bool>>>,
    abort: AbortHandle,
}

impl ContactsPairing {
    pub fn links(&self) -> &PairingLinks {
        &self.links
    }

    pub fn poll(&self) -> Option<PairingEvent> {
        self.rx.lock().ok()?.try_recv().ok()
    }

    /// Unix seconds the current links were built.
    pub fn links_built_at(&self) -> u64 {
        self.built_at
    }

    /// Rebuild the links with a fresh timestamp when they are more than
    /// [`PAIRING_LINK_MAX_AGE_SECS`] old at `now`; returns whether they were.
    /// The pairing itself (app key, challenge, the open subscription) is
    /// unchanged, so an answer to either link completes it.
    pub fn refresh_links_if_stale(&mut self, now: u64) -> Result<bool, String> {
        if !pairing_link_is_stale(self.built_at, now) {
            return Ok(false);
        }
        let r = &self.recipe;
        let links = contacts::pairing_links(&r.app, &r.app_name, &r.relay, now, &r.challenge)?;
        log::info!(
            "[signet] contacts pairing: link was {}s old, rebuilt (t={now})",
            now.saturating_sub(self.built_at)
        );
        self.links = links;
        self.built_at = now;
        Ok(true)
    }

    /// My Signet said the typed code matched: keep the grant (unless a
    /// conflicting answer has arrived).
    pub fn confirm(&self) {
        if let Some(tx) = self.confirm.lock().ok().and_then(|mut g| g.take()) {
            let _ = tx.send(true);
        }
    }

    /// Abandon the pairing; nothing is stored.
    pub fn cancel(&self) {
        if let Some(tx) = self.confirm.lock().ok().and_then(|mut g| g.take()) {
            let _ = tx.send(false);
        }
        self.abort.abort();
    }
}

impl Drop for ContactsPairing {
    fn drop(&mut self) {
        let unanswered = self.confirm.lock().map(|g| g.is_some()).unwrap_or(true);
        if unanswered {
            self.abort.abort();
        }
    }
}

// ─── Invite inbox handle ────────────────────────────────────────────────────

/// Invites to this install's runtime key, already filtered by the receive
/// policy ([`invite::admit`]): the sender is in the played-with book (or a
/// verified attestation moves a persona in the book to a new runtime key),
/// and is not a blocked contact. Everything else was dropped silently. Each
/// invite is checked again against the latest book and contacts when polled.
/// Closes on drop and on sign-out.
///
/// It has **its own relay connection**, opened by [`Signet::inbox`]: a
/// subscription for `kinds:[1059], #p:[own runtime key]`. Nothing naming a
/// persona is ever sent on it.
pub struct InviteInbox {
    rx: Mutex<mpsc::Receiver<Invite>>,
    abort: AbortHandle,
    inner: Arc<Inner>,
    book: PlayedWithBook,
}

impl InviteInbox {
    pub fn poll(&self) -> Option<Invite> {
        let rx = self.rx.lock().ok()?;
        loop {
            let mut inv = rx.try_recv().ok()?;
            match recheck(&self.inner, &self.book, &inv, unix_now()) {
                Verdict::Admit(contact) => {
                    inv.contact = contact;
                    return Some(inv);
                }
                Verdict::Drop(e) => {
                    log::debug!("[signet inbox] withdrew {} before showing: {e}", inv.id)
                }
                Verdict::Closed => {}
            }
        }
    }
}

impl Drop for InviteInbox {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

const INBOX_QUEUE: usize = 64;
const INBOX_SEEN_MAX: usize = 4096;

fn friendly(e: nip46::Error) -> String {
    match e {
        nip46::Error::Timeout => "My Signet didn't answer. Open My Signet and try again.".into(),
        nip46::Error::Signer(m) => format!("My Signet said no ({m})."),
        nip46::Error::Connect(m) => format!("Couldn't reach the relays ({m})."),
        nip46::Error::Uri(m) | nip46::Error::Key(m) => format!("Sign-in data is unusable ({m})."),
    }
}

/// Open the played-with book of `persona` in the crate's data folder.
fn open_book(store: &Store, app_id: &str, persona: &PublicKey) -> PlayedWithBook {
    PlayedWithBook::open(&store.dir().join(BOOK_DIR), persona, app_id)
}

impl Signet {
    /// Open with live relays. Loads any saved session, attestation, profile
    /// and contacts from `cfg.data_dir` (offline; this is resume). The first
    /// open after an upgrade from a version that published the attestation
    /// also collects the ids of those old public notes (see
    /// [`Signet::old_public_note_ids`]); it never retracts them by itself.
    pub fn open(cfg: SignetConfig, runtime_keys: Keys) -> Signet {
        Self::with_connector(cfg, runtime_keys, Arc::new(WsConnector))
    }

    /// Open over any relay [`Connector`] (tests use [`crate::relay::FakeNetwork`]).
    pub fn with_connector(
        cfg: SignetConfig,
        runtime_keys: Keys,
        connector: Arc<dyn Connector>,
    ) -> Signet {
        let store = Store::new(&cfg.data_dir);
        let now = unix_now();
        let me = runtime_keys.public_key();
        // The old store first: it still holds the evidence of what was published.
        let unattributed = legacy::migrate(&store, &cfg.app_id, &me);
        if unattributed > 0 {
            log::warn!(
                "[signet] {unattributed} old withdrawal journal(s) named no persona and could not be kept"
            );
        }
        let session = store
            .load::<PersistedSession>(store::SESSION)
            .and_then(|s| PublicKey::from_hex(&s.persona).ok().map(|p| (s, p)));
        // A used-keys store that is unreadable cannot say which keys were
        // used. Not knowing is treated as "used": a key is only ever too
        // cautious. The store is rewritten at once with the current key in it.
        let my_hash = runtime_hash(&me);
        let (mut keys, damaged) = match store.load_keep::<RuntimeKeys>(store::RUNTIME_KEYS) {
            Loaded::Ok(k) => (k, false),
            Loaded::Absent => (RuntimeKeys::default(), false),
            Loaded::Damaged => (RuntimeKeys::default(), true),
        };
        let retired = keys.retired.contains(&my_hash);
        let used = retired || keys.used.contains(&my_hash) || damaged;
        if damaged {
            keys.add_used(my_hash);
            if let Err(e) = store.save(store::RUNTIME_KEYS, &keys) {
                log::warn!("[signet] could not rewrite the used runtime keys: {e}");
            }
        }
        let mut st = State {
            session: None,
            persona: None,
            attestation: None,
            profile: None,
            grant: None,
            snapshot: None,
            kept_blocks: Vec::new(),
            retired,
            used,
            signer: None,
            sharing_signers: HashMap::new(),
            sign_in_gen: 0,
            permission_gen: 0,
            shared_name: None,
            book: None,
            old_notes: OldNotes::empty(),
            friends: friend::FriendState::default(),
        };
        let record = store.load::<SignInRecord>(store::SIGNIN);
        if let Some((s, p)) = session {
            st.persona = Some(p);
            st.session = Some(s);
            st.book = Some(open_book(&store, &cfg.app_id, &p));
            match record {
                Some(r) if r.persona == p.to_hex() => st.shared_name = r.display_name,
                Some(_) => store.remove(store::SIGNIN),
                None => {}
            }
        } else if let Some((r, p)) = record
            .filter(|r| !r.signer)
            .and_then(|r| PublicKey::from_hex(&r.persona).ok().map(|p| (r, p)))
        {
            // Signed in by Sign in with Signet, with no bunker: no session, no attestation.
            st.persona = Some(p);
            st.shared_name = r.display_name;
            st.book = Some(open_book(&store, &cfg.app_id, &p));
        } else {
            store.remove(store::SIGNIN);
            // Leftovers of a signed-in life whose session is gone. Nothing is
            // owed any more (the attestation was never published by this
            // version), so they simply go; but not before the migration has
            // written down the id of what an older version published.
            if store.exists(store::OLD_PUBLIC_NOTES) {
                store.remove_with_asides(store::ATTESTATION);
            }
            store.remove(store::PROFILE);
        }
        st.old_notes = OldNotes::load(&store, st.persona.as_ref());
        if let (Some(persona), Some(ev)) = (st.persona, store.load::<Event>(store::ATTESTATION)) {
            match verify_attestation_event(&cfg.app_id, &ev, &me, now) {
                Ok(info) if info.persona == persona => st.attestation = Some((ev, info)),
                // Expired or not ours: gone, once the migration has noted it.
                _ if store.exists(store::OLD_PUBLIC_NOTES) => store.remove(store::ATTESTATION),
                _ => {}
            }
        }
        if let (Some(persona), Some(p)) = (st.persona, store.load::<CachedProfile>(store::PROFILE))
            && p.persona == persona.to_hex()
        {
            st.profile = Some(p);
        }
        if let Some(g) = store.load::<Grant>(store::GRANT) {
            // Only the persona that paired it may use it.
            if g.is_well_formed() && st.persona.is_some_and(|p| g.is_for(&p)) {
                let had = store.exists(store::SNAPSHOT);
                let snapshot = store.load::<Snapshot>(store::SNAPSHOT);
                if had && snapshot.is_none() {
                    log::warn!("[signet] the contacts copy cannot be read; its blocks apply again at the next contacts sync");
                }
                st.snapshot = snapshot.filter(|s| s.projection.grant_id == g.grant_id);
                st.grant = Some(g);
            } else {
                store.remove(store::GRANT);
                store.remove(store::SNAPSHOT);
            }
        }
        match store.load_keep::<KeptBlocks>(store::KEPT_BLOCKS) {
            Loaded::Ok(k) if st.persona.is_some_and(|p| p.to_hex() == k.persona) => {
                st.kept_blocks = k
                    .blocked
                    .iter()
                    .filter_map(|h| PublicKey::from_hex(h).ok())
                    .collect();
            }
            Loaded::Ok(_) => store.remove(store::KEPT_BLOCKS),
            // Left where it is: its blocks cannot be read, but they are not thrown away.
            Loaded::Damaged => {
                log::warn!("[signet] the kept blocks cannot be read; they do not apply until they can")
            }
            Loaded::Absent => {}
        }
        st.friends = friend::load(&store, &me, st.persona, now);
        let persona_relay = connector.connect_main(&cfg.relays);
        let (policy, _) = watch::channel(0u64);
        let signet = Signet {
            inner: Arc::new(Inner {
                cfg,
                runtime_keys,
                connector,
                persona_relay,
                store,
                state: Mutex::new(st),
                policy,
                lookup: tokio::sync::Mutex::new(()),
            }),
        };
        signet.start_friend_listeners();
        signet
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.lock()
    }

    pub fn config(&self) -> &SignetConfig {
        &self.inner.cfg
    }

    pub fn runtime_pubkey(&self) -> PublicKey {
        self.inner.runtime_keys.public_key()
    }

    /// This runtime key was retired at sign-out: open a new [`Signet`] on a
    /// fresh key (and use that key in the transport) before signing in.
    pub fn runtime_key_retired(&self) -> bool {
        self.state().retired
    }

    /// A sign-in on this device already used this runtime key (the install
    /// is signed in with it now, or was, or its session was lost), so
    /// [`Signet::sign_in`] refuses it. The app replaces its runtime key (and
    /// the transport's) and opens a new [`Signet`] on the new key **before
    /// every sign-in**; check this first and rotate when it is true.
    pub fn runtime_key_used(&self) -> bool {
        self.state().used
    }

    /// Why [`Signet::sign_in`] would fail at once, if it would.
    pub fn sign_in_refusal(&self) -> Option<SignInRefusal> {
        let st = self.state();
        if st.retired {
            Some(SignInRefusal::KeyRetired)
        } else if st.used {
            Some(SignInRefusal::KeyAlreadyUsed)
        } else {
            None
        }
    }

    pub fn is_signed_in(&self) -> bool {
        self.state().signed_in()
    }

    /// Whether a NIP-46 signer is behind the sign-in, so an attestation can be
    /// minted. `false` when signed out, and for a persona that signed in with
    /// Signet and no bunker ([`SignInEvent::NoBunker`]).
    pub fn has_signer(&self) -> bool {
        self.state().session.is_some()
    }

    /// Whether this install receives invites and friend links: on a live key
    /// and attestable, by a signer behind the sign-in or by a stored
    /// attestation that has not run out. (Contacts and old-note retraction
    /// still need the signer: see [`Signet::has_signer`].)
    pub fn accepting_invites(&self) -> bool {
        self.state().accepting_invites()
    }

    /// [`Signet::accepting_invites`] at a given time (tests of the expiry rule).
    #[doc(hidden)]
    pub fn accepting_invites_at(&self, now: u64) -> bool {
        self.state().accepting_invites_at(now)
    }

    pub fn persona(&self) -> Option<PublicKey> {
        self.state().persona
    }

    /// The name to show for the signed-in persona; `None` when signed out. In
    /// order: the handle My Signet shared at sign-in (the persona's own name
    /// there, which needs no public profile), the persona's kind 0 name, a
    /// short npub. (My Signet's NIP-46 hands over no name of its own.)
    pub fn display_name(&self) -> Option<String> {
        let st = self.state();
        let persona = st.persona?;
        Some(
            st.shared_name
                .clone()
                .or_else(|| st.profile.as_ref().and_then(|p| p.name.clone()))
                .unwrap_or_else(|| contacts::short_npub(&persona)),
        )
    }

    // ── Attestation (kept on the phone, never published) ──

    /// The current attestation (verified for this runtime key when loaded or minted).
    pub fn attestation(&self) -> Option<PersonaInfo> {
        self.state().attestation.as_ref().map(|(_, i)| i.clone())
    }

    /// The attestation as event JSON, for the encrypted game connection's
    /// hello / welcome slot and for invites. `None` once it has expired (peers
    /// would refuse it).
    pub fn attestation_json(&self) -> Option<String> {
        let now = unix_now();
        self.state()
            .attestation
            .as_ref()
            .filter(|(_, i)| now <= i.valid_until)
            .and_then(|(e, _)| serde_json::to_string(e).ok())
    }

    pub fn attestation_event(&self) -> Option<Event> {
        self.state().attestation.as_ref().map(|(e, _)| e.clone())
    }

    /// Signed in, and the attestation is missing, expired or under 7 days.
    pub fn needs_refresh(&self, now: u64) -> bool {
        let st = self.state();
        st.session.is_some()
            && !st.retired
            && st
                .attestation
                .as_ref()
                .is_none_or(|(_, i)| crate::attestation::needs_refresh(i.valid_until, now))
    }

    /// Signed in with no signer, and the attestation (from
    /// [`Signet::ask_online_permission`]) is still valid but has under 7 days
    /// left: time to ask again. Never true with a signer
    /// ([`Signet::needs_refresh`] covers that) or with no attestation.
    pub fn permission_renewal_due(&self, now: u64) -> bool {
        let st = self.state();
        st.persona.is_some()
            && st.session.is_none()
            && !st.retired
            && st.attestation.as_ref().is_some_and(|(_, i)| {
                now <= i.valid_until && crate::attestation::needs_refresh(i.valid_until, now)
            })
    }

    /// **Ask My Signet to play online**: My Signet's `?action=app-permission`
    /// request for `online-play`. My Signet signs this install's attestation
    /// template as the signed-in persona; for a child's persona the guardian
    /// approves on their phone. The answer is a stored gift wrap on a relay
    /// of its own (kit rule 7), chosen as Sign in with Signet chooses
    /// ([`signin::relay_order`]: the first that confirms the subscription is
    /// named in the link). On approval the attestation is stored exactly as
    /// a bunker-signed one, so [`Signet::attestation`] and every peer path
    /// work unchanged.
    ///
    /// Refused when signed out or on a retired runtime key. It works with or
    /// without a bunker. A newer ask, a sign-out or a change of persona while
    /// waiting drops the answer. Nothing is persisted while waiting: the ask
    /// does not outlive this process.
    pub fn ask_online_permission(&self) -> PermissionAsk {
        self.ask_online_permission_within(self.inner.cfg.permission_wait)
    }

    /// How long [`Signet::ask_online_permission`] waits for an answer.
    pub fn permission_wait(&self) -> Duration {
        self.inner.cfg.permission_wait
    }

    /// [`Signet::ask_online_permission`] that waits `wait` for the answer
    /// instead of [`SignetConfig::permission_wait`]: a fresh link for the
    /// same wait, so the person's clock does not start over. The newer ask
    /// supersedes any older one, whose answer is then dropped.
    pub fn ask_online_permission_within(&self, wait: Duration) -> PermissionAsk {
        let (tx, rx) = mpsc::channel();
        let snapshot = {
            let mut st = self.state();
            if st.retired {
                Err(RETIRED_KEY)
            } else if let Some(p) = st.persona {
                // Only an ask that goes ahead supersedes a pending one: a
                // refused ask must not throw away a guardian's approval.
                st.permission_gen += 1;
                Ok((p, st.sign_in_gen, st.permission_gen))
            } else {
                Err(permission::NOT_SIGNED_IN)
            }
        };
        let app_link = Arc::new(OnceLock::new());
        let relay_host = Arc::new(OnceLock::new());
        let live = Arc::new(AskLive::default());
        let refused = |reason: &str, rx| {
            let _ = tx.send(PermissionEvent::Failed {
                reason: reason.to_string(),
            });
            PermissionAsk {
                app_link: app_link.clone(),
                relay_host: relay_host.clone(),
                live: live.clone(),
                rx: Mutex::new(rx),
                abort: runtime().spawn(async {}).abort_handle(),
            }
        };
        let (persona, sign_in_gen, ask_gen) = match snapshot {
            Ok(v) => v,
            Err(reason) => return refused(reason, rx),
        };
        let cfg = &self.inner.cfg;
        let origin = cfg.signin_origin.clone().unwrap_or_default();
        let Some(reason) = cfg.permission_reason.clone() else {
            return refused(permission::BAD_REASON, rx);
        };
        let candidates = signin::relay_order(&cfg.signin_relays, &cfg.relays);
        // Say what is wrong with the request itself before blaming the relays.
        let template = unsigned_attestation(
            &cfg.app_id,
            &persona,
            &self.inner.runtime_keys.public_key(),
            unix_now(),
        );
        // (Any usable relay will do: a player relay that is unusable for the
        // request is skipped later, not a reason to refuse.)
        let probe = "wss://relay.invalid";
        if let Err(e) = permission::PermissionRequest::new(
            &origin,
            &cfg.app_name,
            &reason,
            &template,
            probe,
            unix_now(),
        ) {
            return refused(e, rx);
        }
        if candidates.is_empty() {
            return refused(signin::NO_RELAY, rx);
        }
        let inner = self.inner.clone();
        let (link, host) = (app_link.clone(), relay_host.clone());
        let ask = AskSpec {
            persona,
            sign_in_gen,
            ask_gen,
            origin,
            reason,
            wait,
        };
        let shared = live.clone();
        let handle = runtime().spawn(async move {
            let ev = permission_flow(&inner, ask, candidates, (link, host, shared), &tx).await;
            let _ = tx.send(ev);
        });
        PermissionAsk {
            app_link,
            relay_host,
            live,
            rx: Mutex::new(rx),
            abort: handle.abort_handle(),
        }
    }

    /// Ask the persona (one tap in My Signet) to sign a fresh attestation.
    /// It is stored on the phone and published nowhere.
    pub fn refresh_attestation(&self) -> Task<Result<PersonaInfo, String>> {
        let inner = self.inner.clone();
        Task::spawn(async move {
            let persona = inner.lock().persona.ok_or("not signed in")?;
            if inner.lock().session.is_none() {
                return Err(signin::NO_SIGNER.to_string());
            }
            let signer = signer(&inner).await?;
            mint(&inner, &signer, persona).await
        })
    }

    // ── Sign-in ──

    /// Start a sign-in. Cancels any sign-in already running. **Refused on a
    /// runtime key that was retired, or that any earlier sign-in on this
    /// device used** ([`Signet::sign_in_refusal`]; the `Failed` event says
    /// so): every sign-in gets a new runtime key, so one key never carries
    /// two personas, whatever `session.json` says. The app rotates its key
    /// and opens a new [`Signet`] first.
    pub fn sign_in(&self) -> SignIn {
        let (tx, rx) = mpsc::channel();
        let committed = Arc::new(AtomicBool::new(false));
        let (generation, refusal) = {
            let mut st = self.state();
            st.sign_in_gen += 1;
            let refusal = if st.retired {
                Some(RETIRED_KEY)
            } else if st.used {
                Some(RUNTIME_KEY_USED)
            } else {
                None
            };
            (st.sign_in_gen, refusal)
        };
        let failed = |reason: String, rx, committed| {
            let _ = tx.send(SignInEvent::Failed { reason });
            let abort = runtime().spawn(async {}).abort_handle();
            SignIn {
                uri: String::new(),
                app_link: Arc::new(OnceLock::new()),
                rx: Mutex::new(rx),
                abort,
                committed,
            }
        };
        if let Some(reason) = refusal {
            return failed(reason.into(), rx, committed);
        }
        let cfg = &self.inner.cfg;
        let started =
            PendingPair::start(self.inner.persona_relay.clone(), &cfg.app_name, NIP46_PERMS);
        let (uri, pending) = match started {
            Ok(v) => v,
            Err(e) => return failed(friendly(e), rx, committed),
        };
        let app_link = crate::mysignet_app_link(&uri, cfg.signin_callback.as_deref());
        let inner = self.inner.clone();
        let flag = committed.clone();
        let handle = runtime().spawn(async move {
            let ev = sign_in_flow(&inner, pending, generation, &tx, &flag).await;
            let _ = tx.send(ev);
        });
        SignIn {
            uri,
            app_link: Arc::new(OnceLock::from(app_link)),
            rx: Mutex::new(rx),
            abort: handle.abort_handle(),
            committed,
        }
    }

    /// **Sign in with Signet** (section 5.1 of the game's spec): My Signet's `?auth=1` relay-mode
    /// sign-in, the main way in. It works for private personas: the answer
    /// carries the persona's own handle (when the person shares it) and a
    /// `bunker://` to sign the attestation with.
    ///
    /// Same handle and events as [`Signet::sign_in`]; the differences:
    ///
    /// - [`SignIn::app_link`] is the request link to open once
    ///   [`SignInEvent::AwaitingApproval`] arrives (the answer is delivered
    ///   once, so nothing may be opened before a relay is listening). It is
    ///   empty until then: the relays are tried in turn
    ///   ([`signin::relay_order`], each on a connection of its own) until one
    ///   confirms the subscription, and only that relay is named in the link.
    ///   From then on the attempt never moves to another relay. If none
    ///   opens, `Failed` carries a headline and a line per relay.
    ///   There is no QR ([`SignIn::has_qr`] is `false`).
    /// - [`SignInEvent::Connected`] follows a verified answer. With a
    ///   `bunker://` the flow goes on to [`SignInEvent::Attested`] as before;
    ///   without one (a direct-child persona) it ends in
    ///   [`SignInEvent::NoBunker`]: signed in by name, no attestation.
    /// - Declined in My Signet, a timeout ([`SignetConfig::pairing_timeout`])
    ///   and a relay that closes the request end in `Failed`; nothing is kept then.
    ///
    /// The same runtime-key rules as [`Signet::sign_in`] apply. The origin comes
    /// from [`SignetConfig::signin_origin`], the name from `app_name`, the relay
    /// is the first relay that opens.
    pub fn sign_in_with_signet(&self) -> SignIn {
        let (tx, rx) = mpsc::channel();
        let committed = Arc::new(AtomicBool::new(false));
        let (generation, refusal) = self.begin_attempt();
        let refused = |reason: String, rx, committed| {
            let _ = tx.send(SignInEvent::Failed { reason });
            let abort = runtime().spawn(async {}).abort_handle();
            SignIn {
                uri: String::new(),
                app_link: Arc::new(OnceLock::new()),
                rx: Mutex::new(rx),
                abort,
                committed,
            }
        };
        if let Some(reason) = refusal {
            return refused(reason.into(), rx, committed);
        }
        let cfg = &self.inner.cfg;
        let origin = cfg.signin_origin.clone().unwrap_or_default();
        let candidates = signin::relay_order(&cfg.signin_relays, &cfg.relays);
        if candidates.is_empty() {
            // Say what is wrong with the request: a bad origin before a missing relay.
            let reason = signin::Request::new(&origin, &cfg.app_name, "", unix_now())
                .err()
                .unwrap_or(signin::NO_RELAY);
            return refused(reason.into(), rx, committed);
        }
        let app_link = Arc::new(OnceLock::new());
        let inner = self.inner.clone();
        let flag = committed.clone();
        let link = app_link.clone();
        let handle = runtime().spawn(async move {
            let ev =
                signet_auth_flow(&inner, origin, candidates, link, generation, &tx, &flag).await;
            let _ = tx.send(ev);
        });
        SignIn {
            uri: String::new(),
            app_link,
            rx: Mutex::new(rx),
            abort: handle.abort_handle(),
            committed,
        }
    }

    /// Cancel any sign-in running and say whether this key may sign in.
    fn begin_attempt(&self) -> (u64, Option<&'static str>) {
        let mut st = self.state();
        st.sign_in_gen += 1;
        let refusal = if st.retired {
            Some(RETIRED_KEY)
        } else if st.used {
            Some(RUNTIME_KEY_USED)
        } else {
            None
        };
        (st.sign_in_gen, refusal)
    }

    /// Sign out and fully separate this persona from the next one.
    ///
    /// Before this returns: forgets the NIP-46 session, persona, attestation
    /// (the stored copy and its aside copies too), profile, contacts grant,
    /// contact cache and kept blocks; closes open inboxes; and **retires this
    /// runtime key**: this `Signet` (and any re-opened on the same key)
    /// refuses to sign in again. Nothing is sent anywhere: the attestation was
    /// never published, so there is nothing to withdraw. The persona's
    /// played-with book stays on the phone (it is theirs), as do the ids of
    /// any old public notes ([`Signet::old_public_note_ids`]).
    ///
    /// The app must then replace its runtime key / `Identity` (the
    /// transport's key too) and open a new `Signet` on the new key.
    pub fn sign_out(&self) -> Task<SignOutOutcome> {
        let (signed_out, friend_links_dropped) = {
            let mut st = self.state();
            let signed_out = st.signed_in();
            let friend_links_dropped = st.friends.clear();
            st.sign_in_gen += 1;
            st.session = None;
            st.persona = None;
            st.attestation = None;
            st.profile = None;
            st.shared_name = None;
            st.signer = None;
            st.sharing_signers.clear();
            st.grant = None;
            st.snapshot = None;
            st.kept_blocks.clear();
            st.book = None;
            st.retired = true;
            st.used = true;
            let store = &self.inner.store;
            for f in [
                store::SESSION,
                store::SIGNIN,
                store::PROFILE,
                store::GRANT,
                store::SNAPSHOT,
                store::KEPT_BLOCKS,
                sharing::PROFILE_SESSION,
                sharing::NOTE_SESSION,
                sharing::SCORE_SESSION,
                store::FRIEND_LINKS,
                store::ATTESTATION,
            ] {
                // With every copy a damaged read set aside, and any temp file:
                // they hold the same secrets.
                store.remove_with_asides(f);
            }
            let h = runtime_hash(&self.inner.runtime_keys.public_key());
            let mut keys = match store.load_keep::<RuntimeKeys>(store::RUNTIME_KEYS) {
                Loaded::Ok(k) => k,
                _ => RuntimeKeys::default(),
            };
            keys.add_used(h.clone());
            keys.add_retired(h);
            if let Err(e) = store.save(store::RUNTIME_KEYS, &keys) {
                log::warn!("[signet] could not save the retired runtime key: {e}");
            }
            (signed_out, friend_links_dropped)
        };
        self.inner.policy_changed();
        Task::ready(SignOutOutcome {
            rotate_runtime_key: true,
            signed_out,
            friend_links_dropped,
        })
    }

    // ── Names ──

    /// Fetch the signed-in persona's kind 0 name and cache it.
    pub fn refresh_profile(&self) -> Task<Option<String>> {
        let inner = self.inner.clone();
        Task::spawn(async move { fetch_profile(&inner).await })
    }

    /// Look up one persona's kind 0 name, for a played-with entry that has no
    /// name stored. **One lookup at a time**: calls queue behind each other,
    /// and each asks for a single author, so a relay never sees several
    /// players' npubs asked together (kit rule 7). Call it only when
    /// a screen needs the name.
    ///
    /// Anyone but the signed-in persona is looked up on a **fresh, short-lived
    /// relay connection** of its own: opened for this one request, closed at
    /// EOSE or after [`SignetConfig::fetch_timeout`]. It is never the persona
    /// connection (which carries the sign-in and the persona's own npub) and
    /// never the inbox's. Store the answer with [`PlayedWithBook::set_name`].
    pub fn lookup_name(&self, persona: PublicKey) -> Task<Option<String>> {
        let inner = self.inner.clone();
        Task::spawn(async move { fetch_kind0(&inner, &persona).await })
    }

    // ── Contacts ──

    /// Start the contacts-v2 grant pairing on the first usable relay. Needs a
    /// signed-in persona: the grant is bound to it.
    ///
    /// The code shown must be typed into My Signet; press Continue only after
    /// My Signet says it matched. The ack subscription stays open until
    /// Continue: a second answer for a different grant fails the pairing.
    pub fn pair_contacts(&self) -> Result<ContactsPairing, String> {
        let persona = {
            let st = self.state();
            if st.retired {
                return Err(RETIRED_KEY.into());
            }
            let persona = st.persona.ok_or("Sign in with My Signet first.")?;
            if st.session.is_none() {
                return Err(signin::NO_SIGNER_CONTACTS.into());
            }
            persona
        };
        let cfg = &self.inner.cfg;
        // The link names exactly one relay (the wire format has room for one):
        // the first usable one in the player's order that is not failing.
        let relay_url = decented_relays::RelayPool::global()
            .first_healthy(&cfg.relays, is_valid_contacts_relay_url)
            .ok_or("no wss:// relay configured for contacts pairing")?;
        let app_keys = Keys::generate();
        let challenge = contacts::fresh_challenge();
        let built_at = unix_now();
        let links = contacts::pairing_links(
            &app_keys.public_key(),
            &cfg.app_name,
            &relay_url,
            built_at,
            &challenge,
        )?;
        log::info!(
            "[signet] contacts pairing: started (relay {relay_url}, t={built_at}, app {})",
            short_hex(&app_keys.public_key().to_hex())
        );
        let recipe = LinkRecipe {
            app: app_keys.public_key(),
            app_name: cfg.app_name.clone(),
            relay: relay_url.clone(),
            challenge: challenge.clone(),
        };
        let pair_relay = self
            .inner
            .connector
            .connect(std::slice::from_ref(&relay_url));
        let sub = pair_relay.subscribe(contacts::ack_filters(&app_keys.public_key(), &challenge));
        let (tx, rx) = mpsc::channel();
        let (ctx, crx) = oneshot::channel::<bool>();
        let _ = tx.send(PairingEvent::AwaitingApproval);
        let inner = self.inner.clone();
        let handle = runtime().spawn(async move {
            let p = Pairing {
                pair_relay,
                app_keys,
                challenge,
                persona,
            };
            if let Some(ev) = pairing_flow(&inner, p, sub, crx, &tx).await {
                let _ = tx.send(ev);
            }
        });
        Ok(ContactsPairing {
            links,
            built_at,
            recipe,
            rx: Mutex::new(rx),
            confirm: Mutex::new(Some(ctx)),
            abort: handle.abort_handle(),
        })
    }

    pub fn has_contacts_grant(&self) -> bool {
        self.state().grant.is_some()
    }

    /// Fetch the latest projection. Open inboxes re-check their invites
    /// against it when polled.
    pub fn refresh_contacts(&self) -> Task<Result<ContactsSync, String>> {
        let inner = self.inner.clone();
        Task::spawn(async move { sync_contacts(&inner).await })
    }

    /// A grant exists and the cached contacts are missing or past My Signet's
    /// `expiresAt`. `false` without a grant. Refresh on launch and on resume
    /// ("Open My Signet to refresh your contacts" if it stays stale).
    pub fn contacts_stale(&self, now: u64) -> bool {
        self.state().contacts_stale(now)
    }

    /// The contact picker list: Kin, Kith, Ken (then untiered); blocked never shown.
    pub fn contacts(&self) -> Vec<Contact> {
        self.contact_book().map(|b| b.visible()).unwrap_or_default()
    }

    pub fn contact_book(&self) -> Option<ContactBook> {
        self.state()
            .snapshot
            .as_ref()
            .map(ContactBook::from_snapshot)
    }

    /// Drop the grant and the cached list (revoke it in My Signet too). Its
    /// blocks are kept for this persona.
    pub fn forget_contacts(&self) {
        {
            let mut st = self.state();
            keep_blocks(&self.inner, &mut st);
            st.grant = None;
            st.snapshot = None;
            self.inner.store.remove(store::GRANT);
            self.inner.store.remove(store::SNAPSHOT);
        }
        self.inner.policy_changed();
    }

    // ── The played-with book and invites ──

    /// The signed-in persona's played-with book (the same shared handle every
    /// time). `None` while signed out. It lives in the crate's data folder;
    /// to keep a book elsewhere, open a [`PlayedWithBook`] yourself and pass
    /// it to [`Signet::inbox`].
    pub fn played_with(&self) -> Option<PlayedWithBook> {
        self.state().book.clone()
    }

    /// The inbox relays to put in this install's hello: up to three `wss://`
    /// URLs from the top of the player's relay list. The invite inbox listens
    /// on these.
    pub fn inbox_relays(&self) -> Vec<String> {
        clean_inbox_relays(&self.inner.cfg.relays)
    }

    /// Gift-wrap (NIP-59, kind 1059, one-time wrapper key) an invite to the
    /// runtime key of someone in the played-with book, and publish it to
    /// their inbox relays and nowhere else: the recipient's inbox reads only
    /// those, so a fallback would report "sent" for an invite nobody sees.
    /// With no valid inbox relay on the entry it is refused before anything
    /// is signed (`no inbox relays for this player`); if none of them acks,
    /// it fails (`couldn't reach their relays`). The rumor carries the host name, the room code, the expiry (NIP-40) and
    /// this install's attestation. Each send uses a connection of its own.
    pub fn send_invite(
        &self,
        to: &PlayedWithEntry,
        payload: InvitePayload,
    ) -> Task<Result<(), String>> {
        let now = unix_now();
        if let Err(e) = invite::validate_payload(&payload, now) {
            return Task::ready(Err(format!("invite not sendable: {e}")));
        }
        let Some(to_runtime) = to.runtime_key() else {
            return Task::ready(Err(
                "invite not sendable: the entry holds no runtime key".into()
            ));
        };
        let relays = clean_inbox_relays(&to.inbox_relays);
        if relays.is_empty() {
            return Task::ready(Err("no inbox relays for this player".into()));
        }
        let Some(att) = self.attestation_json() else {
            let msg = if self.attestation().is_some() {
                "Your My Signet link has expired; refresh it first."
            } else {
                "sign in with My Signet first"
            };
            return Task::ready(Err(msg.into()));
        };
        let inner = self.inner.clone();
        Task::spawn(async move {
            let wrap = invite::wrap_invite(&inner.runtime_keys, &att, &to_runtime, &payload)
                .await
                .map_err(|e| e.to_string())?;
            let sent = inner
                .connector
                .connect(&relays)
                .publish_acked(&wrap)
                .wait(inner.cfg.fetch_timeout)
                .await;
            if sent.succeeded() {
                Ok(())
            } else {
                Err("couldn't reach their relays".to_string())
            }
        })
    }

    /// Whether an invite already handed out would still be admitted now
    /// (expiry, still in the book, not blocked). Re-check the invites on
    /// screen after [`Signet::refresh_contacts`] or a "Forget".
    pub fn still_admits(&self, invite: &Invite) -> bool {
        let Some(book) = self.played_with() else {
            return false;
        };
        matches!(
            recheck(&self.inner, &book, invite, unix_now()),
            Verdict::Admit(_)
        )
    }

    /// Listen for invites while the game is open, using the signed-in
    /// persona's own book ([`Signet::played_with`]). See [`Signet::inbox_with`].
    pub fn inbox(&self) -> InviteInbox {
        match self.played_with() {
            Some(book) => self.inbox_with(&book),
            None => self.inbox_with(&PlayedWithBook::open(
                &self.inner.store.dir().join(BOOK_DIR),
                &self.runtime_pubkey(),
                &self.inner.cfg.app_id,
            )),
        }
    }

    /// Listen for invites to this install's runtime key with `book` as the
    /// played-with book. Receives only while signed in as the book's owner.
    ///
    /// It opens **its own relay connection** to [`Signet::inbox_relays`] and
    /// subscribes to `kinds:[1059], #p:[own runtime key]` there. An invite is
    /// delivered only when its sender's runtime key is in the book, or its
    /// attestation verifies, binds the seal's key and names a persona in the
    /// book (then [`Invite::new_runtime`] is set, and the caller updates the
    /// entry with [`PlayedWithBook::rekey`]); and the sender is not a blocked
    /// contact. Everything else is dropped silently. While open it also
    /// re-reads the contacts every [`SignetConfig::contacts_refresh`].
    pub fn inbox_with(&self, book: &PlayedWithBook) -> InviteInbox {
        let me = self.inner.runtime_keys.public_key();
        // Only a persona that can be attested receives invites: a bunker
        // session, or a valid stored attestation (an approval from My Signet).
        let persona = {
            let st = self.state();
            st.persona
                .filter(|p| *p == book.owner() && st.accepting_invites())
        };
        let (tx, rx) = mpsc::sync_channel(INBOX_QUEUE);
        let inner = self.inner.clone();
        let policy = self.inner.policy.subscribe();
        // Senders publish only to the inbox relays a hello names, so the inbox
        // listens there alone: no defaults fallback, no relay a hello cannot name.
        let urls = self.inbox_relays();
        if persona.is_some() && urls.is_empty() {
            log::warn!("[signet] no inbox relays: invites cannot reach this install");
        }
        let handle = match persona.filter(|_| !urls.is_empty()) {
            Some(persona) => {
                // Its own connection: it carries the runtime key and nothing else.
                let relay = self.inner.connector.connect(&urls);
                let book = book.clone();
                runtime().spawn(async move {
                    inbox_loop(inner, relay, book, me, persona, policy, tx).await
                })
            }
            None => runtime().spawn(async {}),
        };
        InviteInbox {
            rx: Mutex::new(rx),
            abort: handle.abort_handle(),
            inner: self.inner.clone(),
            book: book.clone(),
        }
    }

    // ── Old public notes ──

    /// The ids of the attestations and tombstones an earlier version of the
    /// game published (or may have) for `persona`, kept on this phone since
    /// the upgrade. Empty for a persona that never published. The app shows
    /// "Remove my old public note" only while this is not empty.
    pub fn old_public_note_ids(&self, persona: &PublicKey) -> Vec<EventId> {
        self.state()
            .old_notes
            .ids(persona)
            .iter()
            .filter_map(|h| EventId::from_hex(h).ok())
            .collect()
    }

    /// Every persona with something to take back: one that has old public
    /// note ids recorded on this phone, and one the upgrade found any old
    /// record for (a journal, a stored attestation, a straggler, a
    /// discoverability record) even with no id known. The latter is offered
    /// the retraction too: the tap first asks the relays what is there.
    pub fn old_public_note_personas(&self) -> Vec<PublicKey> {
        self.state()
            .old_notes
            .personas()
            .iter()
            .filter_map(|h| PublicKey::from_hex(h).ok())
            .collect()
    }

    /// Ask the signed-in persona (one tap in My Signet) to take back its old
    /// public notes: **one kind 5 with `e` tags only** (no `a`, `k` or `d`
    /// tag, empty content). It goes to the union of the player's relays, the
    /// relays an earlier version still owed a tombstone to, and the pool
    /// defaults, each on a connection of its own. The handle reports each
    /// relay's answer.
    ///
    /// A persona the upgrade found any old record for (not only ids) is
    /// first looked up: for each of those relays, on a fresh short-lived
    /// connection, one REQ `{authors:[persona], kinds:[30420]}` with no `#d`
    /// filter. Events whose `d` tag is the app id are added to the ids. That
    /// lookup runs only here, when the person taps; never at launch.
    ///
    /// The persona is dropped (ids, owed relays and all) only when every
    /// relay of that union that could be reached acked the retraction, none
    /// refused it, and at least one acked (a relay that stayed silent is taken
    /// to be unreachable). Otherwise everything is kept for another try.
    /// **Never automatic**: call it only when the person asks. With nobody
    /// signed in, or nothing for them, the handle reports a failure and
    /// nothing is sent.
    pub fn retract_old_notes(&self) -> Retraction {
        let (tx, rx) = mpsc::channel();
        let (persona, ids, check, owed) = {
            let st = self.state();
            let persona = st.persona.filter(|_| st.session.is_some() && !st.retired);
            let ids: Vec<String> = persona.map(|p| st.old_notes.ids(&p)).unwrap_or_default();
            let check = persona.is_some_and(|p| st.old_notes.needs_check(&p));
            let owed = persona
                .map(|p| st.old_notes.relays_of(&p))
                .unwrap_or_default();
            (persona, ids, check, owed)
        };
        let Some(persona) = persona else {
            let _ = tx.send(RetractEvent::Failed {
                reason: NOT_SIGNED_IN_TO_RETRACT.into(),
            });
            return Retraction::done(rx);
        };
        if ids.is_empty() && !check {
            let _ = tx.send(RetractEvent::Failed {
                reason: "There is nothing to remove.".into(),
            });
            return Retraction::done(rx);
        }
        let inner = self.inner.clone();
        let handle = runtime().spawn(async move {
            let last = retract_flow(&inner, persona, ids, check, owed, &tx).await;
            let _ = tx.send(last);
        });
        Retraction {
            rx: Mutex::new(rx),
            abort: handle.abort_handle(),
        }
    }
}

// ─── Retraction handle ──────────────────────────────────────────────────────

/// What one relay said to the retraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayOutcome {
    /// The relay answered OK.
    Acked,
    /// The relay answered, and said no.
    Refused,
    /// No answer: down, dropped, or too slow.
    Unreachable,
}

/// The end of a retraction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetractReport {
    /// The relays asked (the player's, then any an earlier version still owed
    /// a tombstone to, then the pool defaults) and what each said.
    pub relays: Vec<(String, RelayOutcome)>,
    /// The ids were dropped from this phone: at least one relay took the
    /// retraction, none refused it, and every relay that could be reached
    /// acked. Otherwise they are kept, and the person can try again.
    pub cleared: bool,
}

impl RetractReport {
    pub fn acked(&self) -> usize {
        self.relays
            .iter()
            .filter(|(_, o)| *o == RelayOutcome::Acked)
            .count()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetractEvent {
    /// Asked My Signet to sign the retraction (one tap).
    AwaitingSignature,
    /// One relay answered (events arrive as relays do).
    Relay { url: String, outcome: RelayOutcome },
    /// Every relay has answered or timed out.
    Finished(RetractReport),
    /// Nothing was sent.
    Failed { reason: String },
}

/// One retraction in progress ([`Signet::retract_old_notes`]). Dropping it
/// does not stop it; [`Retraction::cancel`] does.
pub struct Retraction {
    rx: Mutex<mpsc::Receiver<RetractEvent>>,
    abort: AbortHandle,
}

impl Retraction {
    fn done(rx: mpsc::Receiver<RetractEvent>) -> Retraction {
        Retraction {
            rx: Mutex::new(rx),
            abort: runtime().spawn(async {}).abort_handle(),
        }
    }

    pub fn poll(&self) -> Option<RetractEvent> {
        self.rx.lock().ok()?.try_recv().ok()
    }

    /// Stop waiting. A retraction already sent stays sent.
    pub fn cancel(&self) {
        self.abort.abort();
    }
}

/// The relays a retraction goes to, each once, in this order: the player's
/// list, the relays an earlier version still owed a tombstone, the pool
/// defaults (an earlier version fell back to them).
fn retraction_relays(inner: &Inner, owed: &[String]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let defaults = decented_relays::RelayPool::global().defaults().to_vec();
    for u in inner.cfg.relays.iter().chain(owed).chain(&defaults) {
        let k = normalize_relay_url(u);
        if !keys.contains(&k) {
            keys.push(k);
            urls.push(u.clone());
        }
    }
    urls
}

/// Ask each relay, on a fresh connection of its own, for every kind 30420 the
/// persona has there (no `#d`: the app id is not named to the relay). Returns
/// the ids of those whose `d` tag is the app id, and how many relays answered.
async fn scan_for_old_notes(
    inner: &Arc<Inner>,
    persona: &PublicKey,
    urls: &[String],
) -> (Vec<String>, usize) {
    let (rtx, mut rrx) = tokio::sync::mpsc::unbounded_channel::<crate::relay::FetchReport>();
    for url in urls {
        let (inner, url, rtx, persona) = (inner.clone(), url.clone(), rtx.clone(), *persona);
        runtime().spawn(async move {
            let filter = Filter::new()
                .author(persona)
                .kind(Kind::Custom(crate::attestation::ATTESTATION_KIND))
                .limit(legacy::MAX_IDS);
            let relay = inner.connector.connect(std::slice::from_ref(&url));
            // A relay that refused the read has not said it holds nothing.
            let report =
                crate::relay::fetch_unless_refused(&*relay, vec![filter], inner.cfg.fetch_timeout)
                    .await;
            let _ = rtx.send(report);
        });
    }
    drop(rtx);
    let (mut ids, mut answered) = (Vec::new(), 0);
    while let Some(report) = rrx.recv().await {
        answered += usize::from(report.reached());
        for ev in report.events {
            if ev.kind == Kind::Custom(crate::attestation::ATTESTATION_KIND)
                && ev.pubkey == *persona
                && ev.tags.identifier() == Some(inner.cfg.app_id.as_str())
                && ev.verify().is_ok()
            {
                let id = ev.id.to_hex();
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
    }
    (ids, answered)
}

async fn retract_flow(
    inner: &Arc<Inner>,
    persona: PublicKey,
    mut ids: Vec<String>,
    check: bool,
    owed: Vec<String>,
    tx: &mpsc::Sender<RetractEvent>,
) -> RetractEvent {
    let failed = |reason: String| RetractEvent::Failed { reason };
    let urls = retraction_relays(inner, &owed);
    // Never retracted before: ask the relays what the persona has public.
    let mut looked = 0;
    if check {
        let (found, answered) = scan_for_old_notes(inner, &persona, &urls).await;
        looked = answered;
        for id in found {
            if !ids.contains(&id) && ids.len() < legacy::MAX_IDS {
                ids.push(id);
            }
        }
    }
    let event_ids: Vec<EventId> = ids
        .iter()
        .filter_map(|h| EventId::from_hex(h).ok())
        .collect();
    if event_ids.is_empty() {
        if check && looked == 0 {
            return failed("Couldn't reach the relays to look. Try again later.".into());
        }
        if check {
            // Every relay that answered holds nothing: there is nothing to take back.
            return finish(
                inner,
                &persona,
                &urls,
                vec![RelayOutcome::Unreachable; urls.len()],
                true,
            );
        }
        return failed("There is nothing to remove.".into());
    }
    let _ = tx.send(RetractEvent::AwaitingSignature);
    let signer = match signer(inner).await {
        Ok(s) => s,
        Err(e) => return failed(e),
    };
    let unsigned = crate::retract::unsigned_retraction(&persona, &event_ids, unix_now());
    let ev = match signer.sign_event(&unsigned, &persona).await {
        Ok(ev) => ev,
        Err(e) => return failed(friendly(e)),
    };
    if !crate::retract::is_clean_retraction(&ev, &persona, &event_ids) {
        return failed("My Signet signed something other than the removal.".into());
    }
    let (rtx, mut rrx) = tokio::sync::mpsc::unbounded_channel::<(usize, RelayOutcome)>();
    for (i, url) in urls.iter().enumerate() {
        let (inner, ev, url, rtx) = (inner.clone(), ev.clone(), url.clone(), rtx.clone());
        runtime().spawn(async move {
            // A connection to this relay alone.
            let relay = inner.connector.connect(std::slice::from_ref(&url));
            let r = relay.publish_acked(&ev).wait(inner.cfg.fetch_timeout).await;
            let outcome = if r.ok > 0 {
                RelayOutcome::Acked
            } else if r.refused > 0 {
                RelayOutcome::Refused
            } else {
                RelayOutcome::Unreachable
            };
            let _ = rtx.send((i, outcome));
        });
    }
    drop(rtx);
    let mut outcomes = vec![RelayOutcome::Unreachable; urls.len()];
    while let Some((i, outcome)) = rrx.recv().await {
        outcomes[i] = outcome;
        let _ = tx.send(RetractEvent::Relay {
            url: urls[i].clone(),
            outcome,
        });
    }
    let acked = outcomes
        .iter()
        .filter(|o| **o == RelayOutcome::Acked)
        .count();
    let refused = outcomes.contains(&RelayOutcome::Refused);
    finish(inner, &persona, &urls, outcomes, acked >= 1 && !refused)
}

/// End a retraction: drop the persona's old-notes record when `done`.
fn finish(
    inner: &Arc<Inner>,
    persona: &PublicKey,
    urls: &[String],
    outcomes: Vec<RelayOutcome>,
    done: bool,
) -> RetractEvent {
    let mut cleared = false;
    if done {
        let mut st = inner.lock();
        let mut notes = st.old_notes.clone();
        notes.finish(persona);
        match inner.store.save(store::OLD_PUBLIC_NOTES, &notes) {
            Ok(()) => {
                st.old_notes = notes;
                cleared = true;
            }
            Err(e) => log::warn!("[signet] could not drop the retracted note ids: {e}"),
        }
    }
    RetractEvent::Finished(RetractReport {
        relays: urls.iter().cloned().zip(outcomes).collect(),
        cleared,
    })
}

// ─── Flows ──────────────────────────────────────────────────────────────────

async fn sign_in_flow(
    inner: &Arc<Inner>,
    pending: PendingPair,
    generation: u64,
    tx: &mpsc::Sender<SignInEvent>,
    committed: &AtomicBool,
) -> SignInEvent {
    let listening = tx.clone();
    let on_listening = move || {
        let _ = listening.send(SignInEvent::AwaitingApproval);
    };
    let mut signer = match pending
        .await_signer(inner.cfg.pairing_timeout, on_listening)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return SignInEvent::Failed {
                reason: friendly(e),
            };
        }
    };
    signer.set_timeout(inner.cfg.request_timeout);
    let persona = match signer.get_public_key().await {
        Ok(p) => p,
        Err(e) => {
            return SignInEvent::Failed {
                reason: friendly(e),
            };
        }
    };
    let session = signer.persist(&persona);
    let signer = Arc::new(signer);
    if let Err(reason) = commit_sign_in(
        inner,
        generation,
        persona,
        Some((session, signer.clone())),
        None,
        committed,
    ) {
        return SignInEvent::Failed { reason };
    }
    inner.policy_changed();
    let _ = tx.send(SignInEvent::Connected { persona });
    let bg = inner.clone();
    runtime().spawn(async move {
        fetch_profile(&bg).await;
    });
    let _ = tx.send(SignInEvent::AwaitingSignature);
    match mint(inner, &signer, persona).await {
        Ok(info) => SignInEvent::Attested { info },
        Err(reason) => SignInEvent::AttestationFailed { reason },
    }
}

/// A relay that has confirmed a subscription for an answer from My Signet,
/// and the request that subscription belongs to.
struct OpenRelay<R> {
    req: R,
    listen: Arc<dyn Relay>,
    sub: Subscription,
    relay: String,
}

/// Why no relay was opened.
enum OpenFailure {
    /// The request itself could not be built (the sentence to show).
    Request(&'static str),
    /// Every candidate failed, each for this reason.
    Relays(Vec<signin::RelayAttempt>),
}

/// Try each candidate in turn until one confirms the subscription (the
/// answer is delivered to it alone, so it must be listening before the link
/// goes out). Each attempt is a fresh request (`make`, with that relay) on a
/// connection of its own. `what` names the flow in the log.
async fn open_listening_relay<R>(
    inner: &Arc<Inner>,
    what: &str,
    candidates: &[String],
    make: impl Fn(&str) -> Result<(R, Filter), &'static str>,
) -> Result<OpenRelay<R>, OpenFailure> {
    let mut tried: Vec<signin::RelayAttempt> = Vec::new();
    let mut skipped = false;
    for (i, relay) in candidates.iter().enumerate() {
        let host = signin::relay_host(relay);
        log::info!(
            "[signet] {what}: attempt {} of {}: {host}",
            i + 1,
            candidates.len()
        );
        let (req, filter) = match make(relay) {
            Ok(v) => v,
            // This relay cannot be asked over (not `wss://`, too long): skip
            // it. Any other refusal is about the request itself and is final.
            Err(signin::NO_RELAY) => {
                log::info!("[signet] {what}: {host} is not usable as a request relay; skipped");
                skipped = true;
                continue;
            }
            Err(e) => return Err(OpenFailure::Request(e)),
        };
        let listen = inner.connector.connect(std::slice::from_ref(relay));
        let mut sub = listen.subscribe(vec![filter]);
        match confirm_open(&mut sub, inner.cfg.signin_open_wait).await {
            Ok(()) => {
                log::info!("[signet] {what}: {host} is listening; sending the link");
                return Ok(OpenRelay {
                    req,
                    listen,
                    sub,
                    relay: relay.clone(),
                });
            }
            Err((failure, raw)) => {
                log::info!(
                    "[signet] {what}: {host} failed ({}): {raw}",
                    failure.phrase()
                );
                tried.push(signin::RelayAttempt { host, failure });
            }
        }
    }
    if tried.is_empty() && skipped {
        return Err(OpenFailure::Request(signin::NO_RELAY));
    }
    Err(OpenFailure::Relays(tried))
}

/// What listening on an open relay came to.
enum Heard<V> {
    /// An answer `judge` accepted (approval or denial).
    Answer(V),
    /// The relay CLOSED or ended the subscription: no answer can arrive.
    Closed,
}

/// Listen on `sub` until `judge` accepts an event (`Err` is the log reason a
/// wrap was dropped; listening goes on) or the relay closes the
/// subscription. `down` keeps the relay's connection trouble since the link
/// went out, if it has not recovered.
async fn listen_for<V: std::fmt::Debug>(
    sub: &mut Subscription,
    host: &str,
    what: &str,
    down: &mut Option<signin::RelayFailure>,
    mut judge: impl FnMut(&Event) -> Result<V, &'static str>,
) -> Heard<V> {
    use crate::relay::SubStatus;
    let mut status = sub.status_watch();
    let mut watching = true;
    loop {
        tokio::select! {
            changed = status.changed(), if watching => {
                watching = changed.is_ok();
                match status.borrow_and_update().clone() {
                    SubStatus::Closed(text) => {
                        log::info!("[signet] {what}: {host} CLOSED the subscription: {text}");
                        return Heard::Closed;
                    }
                    SubStatus::Down(raw) => {
                        log::info!("[signet] {what}: {host} connection lost: {raw}");
                        *down = Some(match signin::RelayFailure::from_down(&raw) {
                            signin::RelayFailure::Connect => signin::RelayFailure::Dropped,
                            other => other,
                        });
                    }
                    SubStatus::Up => *down = None,
                    SubStatus::Connecting => {}
                }
            }
            msg = sub.recv() => match msg {
                Some(RelayMsg::Event(ev)) => match judge(&ev) {
                    Err(why) => log::info!("[signet] {what}: dropped an answer from {host}: {why}"),
                    Ok(v) => {
                        log::info!("[signet] {what}: an answer arrived on {host}: {v:?}");
                        return Heard::Answer(v);
                    }
                },
                Some(RelayMsg::Eose) => {}
                None => {
                    log::info!("[signet] {what}: {host} ended the subscription");
                    return Heard::Closed;
                }
            },
        }
    }
}

/// Wait for one relay to confirm a sign-in subscription: its EOSE, or (a slow
/// relay) still connected, with no CLOSED and no error, when `within` is up.
/// `Err` carries the failure kind and the relay layer's own words for the log.
async fn confirm_open(
    sub: &mut Subscription,
    within: Duration,
) -> Result<(), (signin::RelayFailure, String)> {
    use crate::relay::SubStatus;
    let verdict = |sub: &Subscription| match sub.status() {
        SubStatus::Down(r) => Err((signin::RelayFailure::from_down(&r), r)),
        SubStatus::Closed(r) => Err((signin::RelayFailure::Closed, r)),
        _ => Ok(()),
    };
    let mut status = sub.status_watch();
    let mut watching = true;
    let deadline = tokio::time::Instant::now() + within;
    loop {
        verdict(sub)?;
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                verdict(sub)?;
                return match sub.status() {
                    SubStatus::Connecting => {
                        Err((signin::RelayFailure::Timeout, "no connection in time".into()))
                    }
                    _ => Ok(()),
                };
            }
            changed = status.changed(), if watching => {
                watching = changed.is_ok();
            }
            msg = sub.recv() => match msg {
                // EOSE was sent after the status was set, so it is the relay's own.
                Some(RelayMsg::Eose) => {
                    verdict(sub)?;
                    return Ok(());
                }
                // Nothing can be an answer before the link exists.
                Some(RelayMsg::Event(_)) => {}
                None => {
                    verdict(sub)?;
                    return Err((signin::RelayFailure::Closed, "subscription ended".into()));
                }
            },
        }
    }
}

/// The Sign in with Signet flow: find a relay that listens, hand over the
/// link, wait for a valid answer, then connect the bunker it names (if any),
/// commit, and mint the attestation.
async fn signet_auth_flow(
    inner: &Arc<Inner>,
    origin: String,
    candidates: Vec<String>,
    link: Arc<OnceLock<String>>,
    generation: u64,
    tx: &mpsc::Sender<SignInEvent>,
    committed: &AtomicBool,
) -> SignInEvent {
    use signin::Verdict;
    let failed = |reason: String| SignInEvent::Failed { reason };
    let make = |relay: &str| {
        let req = signin::Request::new(&origin, &inner.cfg.app_name, relay, unix_now())?
            .with_online_play(&inner.cfg.app_id, inner.runtime_keys.public_key());
        let filter = req.filter();
        Ok((req, filter))
    };
    let OpenRelay {
        req,
        listen,
        mut sub,
        relay,
    } = match open_listening_relay(inner, "sign-in", &candidates, make).await {
        Ok(open) => open,
        Err(OpenFailure::Request(reason)) => return failed(reason.into()),
        Err(OpenFailure::Relays(tried)) => return failed(signin::all_failed(&tried)),
    };
    let host = signin::relay_host(&relay);
    // Listening, so the link may go out. From here this relay is fixed: the
    // link names it, and My Signet answers there.
    let _ = link.set(req.url());
    let _ = tx.send(SignInEvent::AwaitingApproval);
    let mut down: Option<signin::RelayFailure> = None;
    let judge = |ev: &Event| match signin::judge(&req, ev, unix_now()) {
        Verdict::Dropped(why) => Err(why),
        verdict => Ok(verdict),
    };
    let wait = listen_for(&mut sub, &host, "sign-in", &mut down, judge);
    let outcome = tokio::time::timeout(inner.cfg.pairing_timeout, wait).await;
    let verdict = match outcome {
        Err(_) => {
            return failed(signin::no_answer(
                &friendly(nip46::Error::Timeout),
                &host,
                down.as_ref(),
            ));
        }
        Ok(Heard::Closed) => return failed(signin::relay_closed(&host)),
        Ok(Heard::Answer(v)) => v,
    };
    // The attempt is settled: the session key, the challenge and the listening
    // connection have done their work. Drop them before the slow part (the
    // bunker connect and the mint can take minutes).
    drop(sub);
    drop(listen);
    drop(req);
    let (persona, display_name, bunker_uri, online_play) = match verdict {
        Verdict::Approved {
            persona,
            display_name,
            bunker_uri,
            online_play,
        } => (persona, display_name, bunker_uri, online_play),
        Verdict::Declined => return failed(signin::DECLINED.into()),
        Verdict::Dropped(_) => unreachable!("dropped answers are skipped above"),
    };
    // The bunker's one-shot secret has a short life inside My Signet: connect now.
    let signer = match bunker_uri.as_deref().map(nip46::parse_bunker_uri) {
        None => None,
        // Present but unusable: fail, keep nothing, leave the runtime key
        // unused. (Only an absent `bunkerUri` means "no bunker".)
        Some(Err(e)) => {
            log::info!("[signet] sign-in: the bunkerUri did not parse: {e}");
            return failed(signin::BAD_BUNKER.into());
        }
        Some(Ok(b)) => {
            let relay = inner.connector.connect(&b.relays);
            let remote = RemoteSigner::from_bunker(&b, relay, inner.cfg.request_timeout);
            if let Err(e) = remote.connect_with_secret(b.secret.as_deref()).await {
                return failed(friendly(e));
            }
            match remote.get_public_key().await {
                Ok(pk) if pk == persona => {}
                Ok(_) => return failed(signin::WRONG_PROFILE.into()),
                Err(e) => return failed(friendly(e)),
            }
            let session = remote.persist(&persona);
            Some((session, Arc::new(remote)))
        }
    };
    let live = signer.as_ref().map(|(_, s)| s.clone());
    let has_name = display_name.is_some();
    if let Err(reason) = commit_sign_in(inner, generation, persona, signer, display_name, committed)
    {
        return failed(reason);
    }
    inner.policy_changed();
    let _ = tx.send(SignInEvent::Connected { persona });
    match online_play {
        Some(signin::OnlinePlayResult::Approved(event)) => {
            let info = match verify_attestation_event(
                &inner.cfg.app_id,
                &event,
                &inner.runtime_keys.public_key(),
                unix_now(),
            ) {
                Ok(info) if info.persona == persona => info,
                _ => {
                    return SignInEvent::AttestationFailed {
                        reason: "The online statement no longer matches this sign-in.".into(),
                    };
                }
            };
            let mut st = inner.lock();
            if st.sign_in_gen != generation || st.persona != Some(persona) || st.retired {
                return failed(permission::SIGNED_OUT_WHILE_WAITING.into());
            }
            if let Err(reason) = inner.store.save(store::ATTESTATION, &*event) {
                return SignInEvent::AttestationFailed { reason };
            }
            st.attestation = Some((*event, info.clone()));
            drop(st);
            inner.policy_changed();
            return SignInEvent::Attested { info };
        }
        Some(signin::OnlinePlayResult::Declined) => return SignInEvent::NoBunker { persona },
        None => {}
    }
    let Some(signer) = live else {
        return SignInEvent::NoBunker { persona };
    };
    if !has_name {
        // No shared handle: the persona's kind 0 is the next best name.
        let bg = inner.clone();
        runtime().spawn(async move {
            fetch_profile(&bg).await;
        });
    }
    let _ = tx.send(SignInEvent::AwaitingSignature);
    match mint(inner, &signer, persona).await {
        Ok(info) => SignInEvent::Attested { info },
        Err(reason) => SignInEvent::AttestationFailed { reason },
    }
}

/// What an online-permission ask was started for.
struct AskSpec {
    persona: PublicKey,
    /// `sign_in_gen` at the start: a sign-out (or a new sign-in) bumps it.
    sign_in_gen: u64,
    /// `permission_gen` at the start: a newer ask bumps it.
    ask_gen: u64,
    origin: String,
    reason: String,
    /// How long to wait for the answer once the link is out.
    wait: Duration,
}

/// The online-permission flow: find a relay that listens, hand over the
/// link, wait for a valid answer, then store the signed statement as the
/// attestation if the persona and the key are still the ones that asked.
async fn permission_flow(
    inner: &Arc<Inner>,
    ask: AskSpec,
    candidates: Vec<String>,
    (link, relay_host, live): (Arc<OnceLock<String>>, Arc<OnceLock<String>>, Arc<AskLive>),
    tx: &mpsc::Sender<PermissionEvent>,
) -> PermissionEvent {
    use permission::PermissionVerdict as V;
    let failed = |reason: String| PermissionEvent::Failed { reason };
    let runtime_pk = inner.runtime_keys.public_key();
    let make = |relay: &str| {
        let now = unix_now();
        let template = unsigned_attestation(&inner.cfg.app_id, &ask.persona, &runtime_pk, now);
        let req = permission::PermissionRequest::new(
            &ask.origin,
            &inner.cfg.app_name,
            &ask.reason,
            &template,
            relay,
            now,
        )?;
        let filter = req.filter();
        Ok((req, filter))
    };
    let OpenRelay {
        req,
        listen,
        mut sub,
        relay,
    } = match open_listening_relay(inner, "online permission", &candidates, make).await {
        Ok(open) => open,
        Err(OpenFailure::Request(reason)) => return failed(reason.into()),
        Err(OpenFailure::Relays(tried)) => return failed(permission::all_failed(&tried)),
    };
    let host = signin::relay_host(&relay);
    let _ = relay_host.set(host.clone());
    let _ = live.relay.set(Arc::downgrade(&listen));
    let _ = live.status.set(sub.status_watch());
    let _ = link.set(req.url());
    let _ = tx.send(PermissionEvent::Waiting);
    let mut down: Option<signin::RelayFailure> = None;
    let judge = |ev: &Event| match permission::judge(&req, ev, unix_now()) {
        V::Dropped(why) => Err(why),
        verdict => Ok(verdict),
    };
    let wait = listen_for(&mut sub, &host, "online permission", &mut down, judge);
    let verdict = match tokio::time::timeout(ask.wait, wait).await {
        Err(_) => {
            log::info!(
                "[signet] online permission: no answer on {host} (relay trouble: {:?})",
                down.as_ref().map(signin::RelayFailure::phrase)
            );
            return PermissionEvent::TimedOut;
        }
        Ok(Heard::Closed) => return failed(permission::relay_closed(&host)),
        Ok(Heard::Answer(v)) => v,
    };
    drop(sub);
    drop(listen);
    drop(req);
    let event = match verdict {
        V::Approved(ev) => *ev,
        V::Denied => return PermissionEvent::Denied,
        V::Dropped(_) => unreachable!("dropped answers are skipped above"),
    };
    // Kept only for the persona, key and ask that asked, as `mint` keeps one.
    let info = match verify_attestation_event(&inner.cfg.app_id, &event, &runtime_pk, unix_now()) {
        Ok(i) if i.persona == ask.persona => i,
        Ok(_) => return failed(permission::SIGNED_OUT_WHILE_WAITING.into()),
        Err(e) => return failed(e.to_string()),
    };
    let mut st = inner.lock();
    if st.permission_gen != ask.ask_gen {
        return failed(permission::SUPERSEDED.into());
    }
    if st.sign_in_gen != ask.sign_in_gen || st.persona != Some(ask.persona) || st.retired {
        return failed(permission::SIGNED_OUT_WHILE_WAITING.into());
    }
    if let Err(e) = inner.store.save(store::ATTESTATION, &event) {
        return failed(e);
    }
    st.attestation = Some((event, info.clone()));
    drop(st);
    // The persona can be attested now: open inboxes start receiving.
    inner.policy_changed();
    PermissionEvent::Approved(info)
}

/// Make a sign-in the install's: check it is still wanted and that this runtime
/// key may carry it, remember the key as used, then store the session (when
/// there is a signer), the shared handle and the persona. `Err` is the
/// sentence to show; nothing is kept then.
fn commit_sign_in(
    inner: &Arc<Inner>,
    generation: u64,
    persona: PublicKey,
    signer: Option<(PersistedSession, Arc<RemoteSigner>)>,
    shared_name: Option<String>,
    committed: &AtomicBool,
) -> Result<(), String> {
    let mut st = inner.lock();
    if st.sign_in_gen != generation {
        return Err("superseded by another sign-in".into());
    }
    if st.retired {
        return Err(RETIRED_KEY.into());
    }
    if st.used {
        // A runtime key is used by one sign-in, once.
        return Err(RUNTIME_KEY_USED.into());
    }
    if st.persona.is_some_and(|p| p != persona) {
        // One runtime key never carries two personas: sign out first
        // (which retires the key).
        return Err("This install is signed in as someone else. Sign out first.".into());
    }
    // Remember the key as used (hashed) before the session exists.
    let before = match inner.store.load_keep::<RuntimeKeys>(store::RUNTIME_KEYS) {
        Loaded::Ok(l) => l,
        // Damaged: a copy is kept aside; the new list replaces it.
        _ => RuntimeKeys::default(),
    };
    let mut after = before.clone();
    after.add_used(runtime_hash(&inner.runtime_keys.public_key()));
    inner.store.save(store::RUNTIME_KEYS, &after)?;
    // The record that says what Sign in with Signet learned. A plain
    // `nostrconnect` sign-in has nothing to record.
    let record = (signer.is_none() || shared_name.is_some()).then(|| SignInRecord {
        persona: persona.to_hex(),
        display_name: shared_name.clone(),
        signer: signer.is_some(),
    });
    let rollback = |inner: &Inner| {
        let _ = inner.store.save(store::RUNTIME_KEYS, &before);
        inner.store.remove(store::SIGNIN);
    };
    match &record {
        Some(r) => {
            if let Err(e) = inner.store.save(store::SIGNIN, r) {
                rollback(inner);
                return Err(e);
            }
        }
        None => inner.store.remove(store::SIGNIN),
    }
    if let Some((session, _)) = &signer
        && let Err(e) = inner.store.save(store::SESSION, session)
    {
        rollback(inner);
        return Err(e);
    }
    st.used = true;
    if st.persona != Some(persona) {
        st.attestation = None;
        st.profile = None;
        inner.store.remove_with_asides(store::ATTESTATION);
        inner.store.remove(store::PROFILE);
    }
    if st.grant.as_ref().is_some_and(|g| !g.is_for(&persona)) {
        st.grant = None;
        st.snapshot = None;
        inner.store.remove(store::GRANT);
        inner.store.remove(store::SNAPSHOT);
    }
    st.book = Some(open_book(&inner.store, &inner.cfg.app_id, &persona));
    st.shared_name = shared_name;
    match signer {
        Some((session, live)) => {
            st.session = Some(session);
            st.signer = Some(live);
        }
        None => {
            st.session = None;
            st.signer = None;
            // A leftover session for this persona must not outrank the record
            // that says "no signer" after a restart.
            inner.store.remove(store::SESSION);
        }
    }
    st.persona = Some(persona);
    committed.store(true, Ordering::SeqCst);
    Ok(())
}

/// The live signer, or one restored from the saved session (sends `connect`).
async fn signer(inner: &Arc<Inner>) -> Result<Arc<RemoteSigner>, String> {
    let session = {
        let st = inner.lock();
        if let Some(s) = &st.signer {
            return Ok(s.clone());
        }
        st.session.clone().ok_or("not signed in")?
    };
    let s = restore_signer(inner, &session).await?;
    let mut st = inner.lock();
    if st.session.as_ref() == Some(&session) {
        st.signer = Some(s.clone());
    }
    Ok(s)
}

async fn restore_signer(
    inner: &Inner,
    session: &PersistedSession,
) -> Result<Arc<RemoteSigner>, String> {
    let relay = inner.connector.connect(&session.relays);
    let s = RemoteSigner::restore(session, relay, inner.cfg.request_timeout).map_err(friendly)?;
    s.connect().await.map_err(friendly)?;
    Ok(Arc::new(s))
}

/// Ask the persona for a fresh attestation of this runtime key and keep it on
/// the phone. **Nothing is published**: the attestation travels only inside
/// the encrypted game connection and invites.
async fn mint(
    inner: &Arc<Inner>,
    signer: &RemoteSigner,
    persona: PublicKey,
) -> Result<PersonaInfo, String> {
    if inner.lock().retired {
        return Err(RETIRED_KEY.into());
    }
    let runtime_pk = inner.runtime_keys.public_key();
    let unsigned = unsigned_attestation(&inner.cfg.app_id, &persona, &runtime_pk, unix_now());
    let ev = signer
        .sign_event(&unsigned, &persona)
        .await
        .map_err(friendly)?;
    let info = verify_attestation_event(&inner.cfg.app_id, &ev, &runtime_pk, unix_now())
        .map_err(|e| e.to_string())?;
    let mut st = inner.lock();
    if st.persona != Some(persona) || st.retired {
        return Err("signed out while signing".into());
    }
    inner.store.save(store::ATTESTATION, &ev)?;
    st.attestation = Some((ev, info.clone()));
    Ok(info)
}

/// The first 8 hex characters of a key, for logs.
fn short_hex(hex: &str) -> &str {
    &hex[..hex.len().min(8)]
}

struct Pairing {
    pair_relay: Arc<dyn Relay>,
    app_keys: Keys,
    challenge: String,
    persona: PublicKey,
}

async fn pairing_flow(
    inner: &Arc<Inner>,
    p: Pairing,
    mut sub: Subscription,
    mut crx: oneshot::Receiver<bool>,
    tx: &mpsc::Sender<PairingEvent>,
) -> Option<PairingEvent> {
    let failed = |reason: &str| {
        log::info!("[signet] contacts pairing: failed: {reason}");
        Some(PairingEvent::Failed {
            reason: reason.into(),
        })
    };
    log::info!(
        "[signet] contacts pairing: waiting for My Signet's answer (up to {:?})",
        inner.cfg.ack_timeout
    );
    let mut attempted: HashSet<EventId> = HashSet::new();
    let first = match tokio::time::timeout(
        inner.cfg.ack_timeout,
        contacts::next_ack(&mut sub, &p.app_keys, &p.challenge, &mut attempted),
    )
    .await
    {
        Ok(AckNext::Ack(a)) => a,
        _ => return failed("No answer from My Signet in time."),
    };
    let Some(code) = contacts::verification_code(&p.app_keys.public_key(), &p.challenge, &first)
    else {
        return failed("My Signet's answer was unusable.");
    };
    log::info!("[signet] contacts pairing: My Signet answered; showing the verification code");
    let _ = tx.send(PairingEvent::VerificationCode { code });
    // Until Continue, keep listening: anyone who saw the link can answer it,
    // and the real My Signet always answers too. Two different grants = fail.
    let mut open = true;
    loop {
        tokio::select! {
            c = &mut crx => {
                if !matches!(c, Ok(true)) {
                    log::info!("[signet] contacts pairing: cancelled before Continue");
                    return None;
                }
                log::info!("[signet] contacts pairing: Continue pressed");
                break;
            }
            next = contacts::next_ack(&mut sub, &p.app_keys, &p.challenge, &mut attempted), if open => match next {
                AckNext::Ack(a) if contacts::same_grant(&a, &first) => {}
                AckNext::Ack(_) => return failed(PAIRING_CONFLICT),
                AckNext::Capped => return failed(PAIRING_FLOOD),
                AckNext::Closed => open = false,
            },
        }
    }
    // Continue pressed: one last look at anything queued or stored.
    let mut late: Vec<Event> = Vec::new();
    while let Some(msg) = sub.try_recv() {
        if let RelayMsg::Event(ev) = msg {
            late.push(*ev);
        }
    }
    let filters = contacts::ack_filters(&p.app_keys.public_key(), &p.challenge);
    late.extend(fetch(&*p.pair_relay, filters, inner.cfg.fetch_timeout).await);
    for ev in &late {
        match contacts::consider_ack(ev, &p.app_keys, &p.challenge, &mut attempted) {
            Some(AckNext::Ack(a)) if !contacts::same_grant(&a, &first) => {
                return failed(PAIRING_CONFLICT);
            }
            Some(AckNext::Capped) => return failed(PAIRING_FLOOD),
            _ => {}
        }
    }
    let mut grant = Grant::from_ack(&first, &p.app_keys, unix_now());
    grant.persona = Some(p.persona.to_hex());
    {
        let mut st = inner.lock();
        if st.persona != Some(p.persona) || st.retired {
            return failed("Signed out during pairing.");
        }
        if let Err(e) = inner.store.save(store::GRANT, &grant) {
            return failed(&e);
        }
        inner.store.remove(store::SNAPSHOT);
        st.grant = Some(grant);
        st.snapshot = None;
    }
    log::info!("[signet] contacts pairing: grant stored; fetching the contacts");
    let out = match sync_contacts(inner).await {
        Ok(ContactsSync::Revoked) => PairingEvent::Failed {
            reason: "My Signet cancelled this pairing (did the code match?). Start again.".into(),
        },
        Ok(sync) => PairingEvent::Paired { sync },
        Err(reason) => PairingEvent::Failed { reason },
    };
    log::info!("[signet] contacts pairing: done: {out:?}");
    Some(out)
}

// ─── Inbox ──────────────────────────────────────────────────────────────────

enum Verdict {
    Admit(Option<Contact>),
    Drop(InviteError),
    /// Not receiving invites (signed out, retired key).
    Closed,
}

/// The blocks to apply: kept ones, and the current contact book's.
fn block_view(st: &State) -> (Vec<PublicKey>, Option<ContactBook>) {
    (
        st.kept_blocks.clone(),
        st.snapshot.as_ref().map(ContactBook::from_snapshot),
    )
}

fn blocked_in(view: &(Vec<PublicKey>, Option<ContactBook>), persona: &PublicKey) -> bool {
    view.0.contains(persona) || view.1.as_ref().is_some_and(|b| b.is_blocked(persona))
}

/// The receive policy on a freshly opened wrap (see [`invite::admit`]).
fn admit_opened(
    inner: &Inner,
    book: &PlayedWithBook,
    opened: &invite::Opened,
    now: u64,
) -> Result<Invite, InviteError> {
    let view = {
        let st = inner.lock();
        if !st.accepting_invites() {
            return Err(InviteError::NotInBook);
        }
        block_view(&st)
    };
    let a = invite::admit(
        &inner.cfg.app_id,
        book,
        opened,
        &|p| blocked_in(&view, p),
        now,
    )?;
    let contact = view.1.as_ref().and_then(|b| b.find(&a.persona).cloned());
    Ok(Invite {
        payload: opened.payload.clone(),
        persona: a.persona,
        runtime: opened.sender,
        name: a.name,
        contact,
        id: String::new(),
        new_runtime: a.new_runtime,
        attestation: opened.attestation.clone(),
    })
}

/// An invite already admitted, against the latest book and contacts.
fn recheck(inner: &Inner, book: &PlayedWithBook, inv: &Invite, now: u64) -> Verdict {
    let view = {
        let st = inner.lock();
        if !st.accepting_invites() {
            return Verdict::Closed;
        }
        block_view(&st)
    };
    if inv.is_expired(now) {
        return Verdict::Drop(InviteError::Expired);
    }
    if book.by_persona(&inv.persona).is_none() {
        return Verdict::Drop(InviteError::NotInBook);
    }
    if blocked_in(&view, &inv.persona) {
        return Verdict::Drop(InviteError::Blocked);
    }
    Verdict::Admit(view.1.as_ref().and_then(|b| b.find(&inv.persona).cloned()))
}

/// Recently seen wrap ids, oldest evicted first.
#[derive(Default)]
struct Seen {
    set: HashSet<EventId>,
    order: VecDeque<EventId>,
}

impl Seen {
    fn insert(&mut self, id: EventId) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > INBOX_SEEN_MAX
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }
}

/// `false` = the inbox handle is gone.
fn deliver(tx: &mpsc::SyncSender<Invite>, inv: Invite) -> bool {
    match tx.try_send(inv) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(inv)) => {
            log::warn!("[signet inbox] queue full; dropped {}", inv.id);
            true
        }
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

async fn recv_opt(sub: &mut Option<Subscription>) -> Option<RelayMsg> {
    match sub {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
    }
}

async fn inbox_loop(
    inner: Arc<Inner>,
    relay: Arc<dyn Relay>,
    book: PlayedWithBook,
    me: PublicKey,
    persona: PublicKey,
    mut policy: watch::Receiver<u64>,
    tx: mpsc::SyncSender<Invite>,
) {
    let mut sub: Option<Subscription> = None;
    let mut seen = Seen::default();
    let every = inner.cfg.contacts_refresh.max(Duration::from_secs(1));
    let mut refresh = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let (accepting, current) = {
            let st = inner.lock();
            (st.accepting_invites(), st.persona)
        };
        if current != Some(persona) {
            return; // signed out, or another persona: this inbox is over
        }
        if !accepting {
            sub = None;
        } else if sub.is_none() {
            sub = Some(relay.subscribe(vec![invite::inbox_filter(&me, unix_now())]));
        }
        tokio::select! {
            msg = recv_opt(&mut sub) => match msg {
                Some(RelayMsg::Event(ev)) => {
                    if !seen.insert(ev.id) {
                        continue;
                    }
                    let now = unix_now();
                    let gift = match invite::unwrap_for_us(&inner.runtime_keys, &ev, now).await {
                        Ok(g) => g,
                        Err(e) => {
                            log::debug!("[signet inbox] dropped {}: {e}", ev.id);
                            continue;
                        }
                    };
                    // A friend reply has a rumor kind of its own and its own
                    // acceptance rule (a pending link); it is never an invite.
                    if gift.rumor.kind == Kind::Custom(friend::FRIEND_REPLY_RUMOR_KIND) {
                        friend::accept_reply(&inner, &book, gift, now);
                        continue;
                    }
                    let opened = match invite::invite_from_gift(gift, now) {
                        Ok(v) => v,
                        Err(e) => {
                            log::debug!("[signet inbox] dropped {}: {e}", ev.id);
                            continue;
                        }
                    };
                    if opened.sender == me {
                        continue;
                    }
                    match admit_opened(&inner, &book, &opened, now) {
                        Ok(inv) => {
                            if !deliver(&tx, Invite { id: ev.id.to_hex(), ..inv }) {
                                return;
                            }
                        }
                        Err(e) => log::debug!("[signet inbox] refused {}: {e}", ev.id),
                    }
                }
                Some(RelayMsg::Eose) => {}
                None => return,
            },
            changed = policy.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            _ = refresh.tick() => {
                let has_grant = inner.lock().grant.is_some();
                if has_grant && let Err(e) = sync_contacts(&inner).await {
                    log::debug!("[signet inbox] contacts refresh failed: {e}");
                }
            }
        }
    }
}

/// Pull a display name out of kind 0 content.
pub(crate) fn profile_name(content: &str) -> Option<String> {
    if content.len() > 64 * 1024 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    ["display_name", "displayName", "name"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(|x| x.as_str()))
        .map(|s| sanitize_wire_text(s, MAX_PROFILE_NAME).trim().to_string())
        .find(|s| !s.is_empty())
}

/// Own persona's kind 0: fetched and cached.
async fn fetch_profile(inner: &Arc<Inner>) -> Option<String> {
    let persona = inner.lock().persona?;
    let name = fetch_kind0(inner, &persona).await;
    // An answer with no name (or none at all) leaves the cache as it was.
    let name = name?;
    let cached = CachedProfile {
        persona: persona.to_hex(),
        name: Some(name.clone()),
        fetched_at: unix_now(),
    };
    let mut st = inner.lock();
    if st.persona == Some(persona) {
        let _ = inner.store.save(store::PROFILE, &cached);
        st.profile = Some(cached);
    }
    Some(name)
}

/// One persona's kind 0 name. Lookups are serialised: one at a time, one
/// author per request. The signed-in persona's own profile goes over the
/// persona connection; everybody else is asked on a fresh connection that is
/// dropped (closed) as soon as the answer is in, so a relay never sees the
/// own npub and a co-player's, or two co-players', on one connection.
async fn fetch_kind0(inner: &Arc<Inner>, persona: &PublicKey) -> Option<String> {
    let _one_at_a_time = inner.lookup.lock().await;
    let filter = Filter::new().kind(Kind::Metadata).author(*persona).limit(3);
    let own = inner.lock().persona == Some(*persona);
    let events = if own {
        fetch(&*inner.persona_relay, vec![filter], inner.cfg.fetch_timeout).await
    } else {
        let relay = inner.connector.connect(&inner.cfg.relays);
        fetch(&*relay, vec![filter], inner.cfg.fetch_timeout).await
        // `relay` drops here: the sockets close.
    };
    let newest = events
        .into_iter()
        .filter(|e| e.kind == Kind::Metadata && e.pubkey == *persona && e.verify().is_ok())
        .max_by_key(|e| e.created_at)?;
    profile_name(&newest.content)
}

/// Remember the current book's blocks for this persona before the book goes.
fn keep_blocks(inner: &Inner, st: &mut State) {
    let Some(persona) = st.persona else { return };
    if let Some(book) = st.snapshot.as_ref().map(ContactBook::from_snapshot) {
        for pk in book.blocked_keys() {
            if !st.kept_blocks.contains(&pk) {
                st.kept_blocks.push(pk);
            }
        }
    }
    if st.kept_blocks.is_empty() {
        return;
    }
    let kept = KeptBlocks {
        persona: persona.to_hex(),
        blocked: st.kept_blocks.iter().map(|k| k.to_hex()).collect(),
    };
    let _ = inner.store.save(store::KEPT_BLOCKS, &kept);
}

async fn sync_contacts(inner: &Arc<Inner>) -> Result<ContactsSync, String> {
    let (grant, held) = {
        let st = inner.lock();
        (
            st.grant.clone().ok_or("no contacts grant")?,
            st.snapshot.as_ref().map(|s| s.projection.clone()),
        )
    };
    let filter = contacts::projection_filter(&grant).ok_or("contacts grant is damaged")?;
    let relay = inner.connector.connect(std::slice::from_ref(&grant.relay));
    let report = crate::relay::fetch_report(&*relay, vec![filter], inner.cfg.fetch_timeout).await;
    // "Nothing newer" is only true if the relay answered; a relay that could not be
    // reached says nothing about the contacts.
    if !report.reached() {
        return Err("Couldn't reach the relay your contacts are on.".to_string());
    }
    let events = report.events;
    let result = {
        let mut st = inner.lock();
        if st.grant.as_ref() != Some(&grant) {
            return Ok(ContactsSync::Unchanged);
        }
        match contacts::accept_projection(&events, &grant, held.as_ref()) {
            Accepted::Unchanged => ContactsSync::Unchanged,
            Accepted::Revoked => {
                keep_blocks(inner, &mut st);
                st.grant = None;
                st.snapshot = None;
                inner.store.remove(store::GRANT);
                inner.store.remove(store::SNAPSHOT);
                ContactsSync::Revoked
            }
            Accepted::Replace(p) => {
                let snap = Snapshot {
                    v: SNAPSHOT_VERSION,
                    projection: *p,
                    fetched_at: unix_now(),
                };
                inner.store.save(store::SNAPSHOT, &snap)?;
                let contacts = ContactBook::from_snapshot(&snap).visible().len();
                st.snapshot = Some(snap);
                // The new book is authoritative again.
                st.kept_blocks.clear();
                inner.store.remove(store::KEPT_BLOCKS);
                ContactsSync::Updated { contacts }
            }
        }
    };
    inner.policy_changed();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_prefers_display_name_and_sanitises() {
        assert_eq!(
            profile_name(r#"{"name":"alex","display_name":"Alex P"}"#).as_deref(),
            Some("Alex P")
        );
        assert_eq!(
            profile_name(r#"{"name":"  alex  "}"#).as_deref(),
            Some("alex")
        );
        assert_eq!(
            profile_name(r#"{"display_name":"","name":"bo"}"#).as_deref(),
            Some("bo")
        );
        assert_eq!(
            profile_name("{\"name\":\"a\u{202e}b\"}")
                .as_deref()
                .map(|s| s.contains('\u{202e}')),
            Some(false)
        );
        assert_eq!(profile_name("not json"), None);
        assert_eq!(
            profile_name(&format!("{{\"name\":\"{}\"}}", "x".repeat(70_000))),
            None
        );
    }

    #[test]
    fn seen_evicts_oldest_instead_of_clearing() {
        let mut s = Seen::default();
        let ids: Vec<EventId> = (0..INBOX_SEEN_MAX as u32 + 2)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&i.to_be_bytes());
                EventId::from_byte_array(b)
            })
            .collect();
        for id in &ids {
            assert!(s.insert(*id));
        }
        assert!(
            !s.insert(ids[ids.len() - 1]),
            "recent ids are still remembered"
        );
        assert!(s.insert(ids[0]), "the oldest was evicted");
    }

    #[test]
    fn relay_urls_that_differ_only_in_case_port_or_trailing_slash_are_one_relay() {
        assert_eq!(
            normalize_relay_url("wss://Relay.Test/"),
            normalize_relay_url("wss://relay.test")
        );
        assert_ne!(
            normalize_relay_url("wss://relay.test"),
            normalize_relay_url("wss://other.test")
        );
    }
}
