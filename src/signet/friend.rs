//! Friend links (section 5.2 item 4 of the game's spec, kit rule 5).
//!
//! A link reaches someone you have not played with, even while you are
//! offline. The wire (link, mailbox key, two-layer hello) is `decented-invite`;
//! this module is the stateful half:
//!
//! - **Live links** (the link owner): at most [`MAX_LIVE_LINKS`] per persona,
//!   each with `created_at`. Every live link has a **mailbox listener** with a
//!   relay connection of its own (never the inbox's, never the persona's),
//!   subscribed to `kinds:[1059], #p:[mailbox]` on the link's relays since
//!   `created_at` minus two days.
//! - **Waiting hellos**: a hello opens only when its attestation verifies,
//!   is in date and binds exactly the seal's signer. At most
//!   [`MAX_HELLOS_PER_LINK`] wait per link. Nothing is added without a tap:
//!   [`Signet::accept_hello`] or [`Signet::decline_hello`]. The ids handled
//!   either way are kept on disk so a restart does not ask again.
//! - **Using a link** (the other side): [`Signet::use_friend_link`] sends the
//!   hello and keeps a **pending** record `{to, link hash, relays, exp}` so the
//!   friend reply can be recognised (the inbox's third acceptance case).
//! - **Friend reply**: a NIP-59 gift wrap to the hello's signer, with a rumor
//!   of its own kind ([`FRIEND_REPLY_RUMOR_KIND`]), never read as a game invite.
//!
//! Everything lives in `friend-links.json`, scoped to one persona and one
//! runtime key. A link's inner layer is encrypted to the runtime key, so a
//! sign-out or a new runtime key ends every live link
//! ([`SignOutOutcome::friend_links_dropped`], [`Signet::friend_links_dropped_at_open`]).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::Notify;

use decented_invite::{
    BACKDATE_MAX_SECS, FriendLink, Hello, LINK_TTL_DEFAULT, OpenedHello, Reply, open_hello,
    sanitise_name, seal_hello,
};
use nostr::nips::nip59::UnwrappedGift;
use nostr::{Event, EventBuilder, EventId, Filter, Keys, Kind, PublicKey, Timestamp};
use serde::{Deserialize, Serialize};
use tokio::task::AbortHandle;

use super::{Inner, Signet, State, block_view, blocked_in};
use crate::attestation::verify_attestation;
use crate::contacts::short_npub;
use crate::invite::{INBOX_LOOKBACK, expiration_tag};
use crate::played_with::{PlayedWithBook, PlayedWithEntry, clean_inbox_relays};
use crate::relay::{Relay, RelayMsg, Subscription};
use crate::store::{self, Store};
use crate::{Task, runtime, unix_now};

/// The rumor kind of a friend reply. Distinct from a game invite
/// ([`crate::invite::INVITE_RUMOR_KIND`]); like it, it only ever exists inside
/// a seal.
pub const FRIEND_REPLY_RUMOR_KIND: u16 = 20913;
/// Live links per persona.
pub const MAX_LIVE_LINKS: usize = 8;
/// Hellos waiting per link; later ones are dropped.
pub const MAX_HELLOS_PER_LINK: usize = 16;
/// Hellos waiting per link from one sender (seal-signer runtime key).
pub const MAX_HELLOS_PER_SENDER: usize = 2;
/// Pending (outgoing) links kept; the oldest go first.
pub const MAX_PENDING: usize = 16;
/// Handled hello ids remembered; the oldest go first.
const MAX_HANDLED: usize = 2048;
/// Wrap ids a listener remembers, to skip a copy from a second relay.
const SEEN_MAX: usize = 4096;
/// Declined senders remembered (per link, until it lapses); the oldest go first.
const MAX_DECLINED: usize = 512;
/// Accepted senders remembered, for the reply resend; the oldest go first.
const MAX_ACCEPTED: usize = 256;
/// Owed replies kept; the oldest go first.
const MAX_OWED: usize = 64;
/// A repeat hello from someone already added gets the reply again, at most
/// this often per sender.
const RESEND_EVERY_SECS: u64 = 3600;

// A friend reply is read only through the invite inbox's lookback, so a link
// and its backdating must fit in it (a later 30-day default would not).
const _: () = assert!(LINK_TTL_DEFAULT + BACKDATE_MAX_SECS <= INBOX_LOOKBACK);

/// The scheme and host a link is stored with. The app builds the link it
/// shares with its own prefix; this one never leaves the phone.
const STORE_PREFIX: &str = "x://friend";

/// A name goes into a hello as 1-32 characters.
const NAME_CHARS: usize = 32;

/// A link you made and are listening for.
#[derive(Clone, Debug)]
pub struct LiveFriendLink {
    pub link: FriendLink,
    /// Unix seconds.
    pub created_at: u64,
}

/// A link you used and are waiting on: the other side has not added you yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingFriendLink {
    /// The link owner's runtime key.
    pub to: PublicKey,
    /// SHA-256 of the link's canonical JSON.
    pub link: [u8; 32],
    /// The relays the hello went to.
    pub relays: Vec<String>,
    /// When the link, and so this record, lapses (unix seconds).
    pub exp: u64,
}

/// Someone used one of your links and waits for your tap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriendHello {
    /// Hex of [`decented_invite::OpenedHello::id`]; pass it to
    /// [`Signet::accept_hello`] or [`Signet::decline_hello`].
    pub id: String,
    /// The name they gave (sanitised, 1-32 characters), or empty.
    pub name: String,
    /// Hex hash of the link they used.
    pub link: String,
    /// Their persona, from the verified attestation.
    pub persona: PublicKey,
    /// Their runtime key.
    pub runtime: PublicKey,
}

/// What the friend flow tells the app. Collected with [`Signet::take_friend_events`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FriendEvent {
    /// A link you used was answered: they added you, and you added them.
    Added { name: String, persona: PublicKey },
}

/// A sender you turned down on a link: later hellos from the same seal signer
/// or the same attested persona, on that link, are dropped silently.
#[derive(Clone)]
struct Declined {
    link: [u8; 32],
    signer: [u8; 32],
    persona: [u8; 32],
    /// The link's expiry (unix seconds): the record lapses with it.
    exp: u64,
}

/// A sender you added from a link, for the reply resend.
#[derive(Clone)]
struct Accepted {
    link: [u8; 32],
    signer: [u8; 32],
    exp: u64,
    /// When a reply was last sent or tried (unix seconds).
    last_reply: u64,
    /// The wraps of the hellos that were answered: a relay replaying one of
    /// them (at launch, say) is not the friend writing again.
    wraps: Vec<[u8; 32]>,
}

/// A friend reply that is owed: stored until it is published or the link
/// would have lapsed.
#[derive(Clone)]
struct Owed {
    to: PublicKey,
    relays: Vec<String>,
    link: [u8; 32],
    exp: u64,
}

/// A running mailbox listener.
struct Listener {
    abort: AbortHandle,
    /// Wakes the listener to ask the mailbox again.
    requery: Arc<Notify>,
}

#[derive(Clone)]
struct Waiting {
    id: [u8; 32],
    /// The wrap this hello came in (a relay replay is not a repeat hello).
    wrap: [u8; 32],
    link: [u8; 32],
    link_exp: u64,
    opened: OpenedHello,
    persona: PublicKey,
}

#[derive(Default)]
pub(super) struct FriendState {
    live: Vec<LiveFriendLink>,
    pending: Vec<PendingFriendLink>,
    hellos: Vec<Waiting>,
    /// Oldest first.
    handled: Vec<[u8; 32]>,
    declined: Vec<Declined>,
    accepted: Vec<Accepted>,
    owed: Vec<Owed>,
    /// Links that dropped a hello because they were full: when a slot frees,
    /// their mailbox is asked again.
    capped: HashSet<[u8; 32]>,
    events: VecDeque<FriendEvent>,
    listeners: HashMap<[u8; 32], Listener>,
    /// Live links that could not be kept when the store was opened.
    dropped_at_open: usize,
}

impl FriendState {
    /// Forget everything; the number of live links that were going.
    pub(super) fn clear(&mut self) -> usize {
        for (_, l) in self.listeners.drain() {
            l.abort.abort();
        }
        let n = self.live.len();
        self.live.clear();
        self.pending.clear();
        self.hellos.clear();
        self.handled.clear();
        self.declined.clear();
        self.accepted.clear();
        self.owed.clear();
        self.capped.clear();
        self.events.clear();
        n
    }

    fn cap<T>(v: &mut Vec<T>, max: usize) {
        let skip = v.len().saturating_sub(max);
        v.drain(..skip);
    }

    /// When a link has room again, ask its mailbox again: hellos dropped while
    /// it was full come back (dedupe still applies).
    fn requery_if_room(&mut self, link: &[u8; 32]) {
        let waiting = self.hellos.iter().filter(|h| h.link == *link).count();
        if waiting < MAX_HELLOS_PER_LINK
            && self.capped.remove(link)
            && let Some(l) = self.listeners.get(link)
        {
            l.requery.notify_one();
        }
    }

    fn mark_handled(&mut self, id: [u8; 32]) {
        if !self.handled.contains(&id) {
            self.handled.push(id);
        }
        let skip = self.handled.len().saturating_sub(MAX_HANDLED);
        self.handled.drain(..skip);
    }

    /// Drop what has lapsed: links (and their waiting hellos), pending
    /// records, declined and accepted senders, owed replies. `true` if
    /// anything changed.
    fn prune(&mut self, now: u64) -> bool {
        let before = (
            self.live.len(),
            self.pending.len(),
            self.hellos.len(),
            self.declined.len(),
            self.accepted.len(),
            self.owed.len(),
        );
        let listeners = &mut self.listeners;
        self.live.retain(|l| {
            let keep = l.link.exp > now;
            if !keep && let Some(l) = listeners.remove(&l.link.hash()) {
                l.abort.abort();
            }
            keep
        });
        self.pending.retain(|p| p.exp > now);
        self.hellos.retain(|h| h.link_exp > now);
        self.declined.retain(|d| d.exp > now);
        self.accepted.retain(|a| a.exp > now);
        self.owed.retain(|o| o.exp > now);
        let live: HashSet<[u8; 32]> = self.live.iter().map(|l| l.link.hash()).collect();
        self.capped.retain(|c| live.contains(c));
        before
            != (
                self.live.len(),
                self.pending.len(),
                self.hellos.len(),
                self.declined.len(),
                self.accepted.len(),
                self.owed.len(),
            )
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let st = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        for (_, l) in st.friends.listeners.drain() {
            l.abort.abort();
        }
    }
}

// ─── Persistence ────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct LinkRec {
    link: String,
    created_at: u64,
}

#[derive(Serialize, Deserialize)]
struct PendingRec {
    to: String,
    link: String,
    relays: Vec<String>,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
struct DeclinedRec {
    link: String,
    signer: String,
    persona: String,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
struct AcceptedRec {
    link: String,
    signer: String,
    exp: u64,
    last_reply: u64,
    #[serde(default)]
    wraps: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct OwedRec {
    to: String,
    link: String,
    relays: Vec<String>,
    exp: u64,
}

/// `friend-links.json`: one persona's, on one runtime key.
#[derive(Serialize, Deserialize, Default)]
struct FriendFile {
    persona: String,
    runtime: String,
    links: Vec<LinkRec>,
    pending: Vec<PendingRec>,
    handled: Vec<String>,
    #[serde(default)]
    declined: Vec<DeclinedRec>,
    #[serde(default)]
    accepted: Vec<AcceptedRec>,
    #[serde(default)]
    owed: Vec<OwedRec>,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    (s.len() == 64).then_some(())?;
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Read the saved state for `persona` on runtime key `me`. A file for another
/// persona or another runtime key is dropped whole (and its live links
/// counted): their inner layer was for a key we no longer hold.
pub(super) fn load(
    store: &Store,
    me: &PublicKey,
    persona: Option<PublicKey>,
    now: u64,
) -> FriendState {
    let mut fs = FriendState::default();
    let Some(file) = store.load::<FriendFile>(store::FRIEND_LINKS) else {
        return fs;
    };
    let mine = persona.is_some_and(|p| p.to_hex() == file.persona) && file.runtime == me.to_hex();
    let links: Vec<LiveFriendLink> = file
        .links
        .iter()
        .filter_map(|r| {
            let link = FriendLink::find_in(&r.link, now).ok()?;
            Some(LiveFriendLink {
                link,
                created_at: r.created_at,
            })
        })
        .collect();
    if !mine {
        fs.dropped_at_open = links.len();
        store.remove(store::FRIEND_LINKS);
        return fs;
    }
    fs.live = links
        .into_iter()
        .filter(|l| l.link.to == *me)
        .take(MAX_LIVE_LINKS)
        .collect();
    fs.pending = file
        .pending
        .iter()
        .filter_map(|r| {
            Some(PendingFriendLink {
                to: PublicKey::from_hex(&r.to).ok()?,
                link: hex32(&r.link)?,
                relays: clean_inbox_relays(&r.relays),
                exp: r.exp,
            })
        })
        .filter(|p| p.exp > now)
        .collect();
    fs.handled = file.handled.iter().filter_map(|h| hex32(h)).collect();
    fs.declined = file
        .declined
        .iter()
        .filter_map(|r| {
            Some(Declined {
                link: hex32(&r.link)?,
                signer: hex32(&r.signer)?,
                persona: hex32(&r.persona)?,
                exp: r.exp,
            })
        })
        .filter(|d| d.exp > now)
        .collect();
    fs.accepted = file
        .accepted
        .iter()
        .filter_map(|r| {
            Some(Accepted {
                link: hex32(&r.link)?,
                signer: hex32(&r.signer)?,
                exp: r.exp,
                last_reply: r.last_reply,
                wraps: r.wraps.iter().filter_map(|w| hex32(w)).collect(),
            })
        })
        .filter(|a| a.exp > now)
        .collect();
    fs.owed = file
        .owed
        .iter()
        .filter_map(|r| {
            Some(Owed {
                to: PublicKey::from_hex(&r.to).ok()?,
                link: hex32(&r.link)?,
                relays: clean_inbox_relays(&r.relays),
                exp: r.exp,
            })
        })
        .filter(|o| o.exp > now)
        .collect();
    fs
}

impl Inner {
    /// Write the friend state (or remove the file when there is nothing to keep).
    pub(super) fn save_friends(&self, st: &State) {
        let f = &st.friends;
        let Some(persona) = st.persona else {
            self.store.remove(store::FRIEND_LINKS);
            return;
        };
        if f.live.is_empty()
            && f.pending.is_empty()
            && f.handled.is_empty()
            && f.declined.is_empty()
            && f.accepted.is_empty()
            && f.owed.is_empty()
        {
            self.store.remove(store::FRIEND_LINKS);
            return;
        }
        let file = FriendFile {
            persona: persona.to_hex(),
            runtime: self.runtime_keys.public_key().to_hex(),
            links: f
                .live
                .iter()
                .map(|l| LinkRec {
                    link: l.link.encode(STORE_PREFIX),
                    created_at: l.created_at,
                })
                .collect(),
            pending: f
                .pending
                .iter()
                .map(|p| PendingRec {
                    to: p.to.to_hex(),
                    link: hex::encode(p.link),
                    relays: p.relays.clone(),
                    exp: p.exp,
                })
                .collect(),
            handled: f.handled.iter().map(hex::encode).collect(),
            declined: f
                .declined
                .iter()
                .map(|d| DeclinedRec {
                    link: hex::encode(d.link),
                    signer: hex::encode(d.signer),
                    persona: hex::encode(d.persona),
                    exp: d.exp,
                })
                .collect(),
            accepted: f
                .accepted
                .iter()
                .map(|a| AcceptedRec {
                    link: hex::encode(a.link),
                    signer: hex::encode(a.signer),
                    exp: a.exp,
                    last_reply: a.last_reply,
                    wraps: a.wraps.iter().map(hex::encode).collect(),
                })
                .collect(),
            owed: f
                .owed
                .iter()
                .map(|o| OwedRec {
                    to: o.to.to_hex(),
                    link: hex::encode(o.link),
                    relays: o.relays.clone(),
                    exp: o.exp,
                })
                .collect(),
        };
        if let Err(e) = self.store.save(store::FRIEND_LINKS, &file) {
            log::warn!("[signet] could not save the friend links: {e}");
        }
    }
}

// ─── The mailbox listener ───────────────────────────────────────────────────

/// The relays of someone's link this phone will dial: those a hello may name
/// ([`clean_inbox_relays`]: `wss://`, no host on the phone's own network).
/// Anyone can make a link, so it must not get to point this phone at a host
/// on its own network.
fn usable_link_relays(link: &FriendLink) -> Vec<String> {
    clean_inbox_relays(&link.relays)
}

/// What the mailbox subscription asks for: gift wraps to the mailbox key,
/// back to two days before the link was made.
fn mailbox_filter(mailbox: &Keys, created_at: u64) -> Filter {
    Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(mailbox.public_key())
        .since(Timestamp::from(
            created_at.saturating_sub(BACKDATE_MAX_SECS),
        ))
}

/// Open the listener for one live link: its own connection to the link's
/// relays, a subscription for the mailbox, a task that reads it.
fn spawn_listener(inner: &Arc<Inner>, live: &LiveFriendLink) -> Option<Listener> {
    let mailbox = live.link.mailbox(&inner.cfg.app_id).ok()?;
    // `connect`, not `connect_main`: this is the link's relays only, with no
    // default-relay fallback, and a connection that nothing else shares.
    let relay = inner.connector.connect(&live.link.relays);
    let sub = relay.subscribe(vec![mailbox_filter(&mailbox, live.created_at)]);
    let requery = Arc::new(Notify::new());
    let weak = Arc::downgrade(inner);
    let handle = runtime().spawn(mailbox_loop(
        weak,
        relay,
        sub,
        mailbox,
        live.link.clone(),
        live.created_at,
        requery.clone(),
    ));
    Some(Listener {
        abort: handle.abort_handle(),
        requery,
    })
}

async fn mailbox_loop(
    weak: Weak<Inner>,
    relay: Arc<dyn Relay>,
    mut sub: Subscription,
    mailbox: Keys,
    link: FriendLink,
    created_at: u64,
    requery: Arc<Notify>,
) {
    let mut seen: HashSet<EventId> = HashSet::new();
    loop {
        let left = link.exp.saturating_sub(unix_now());
        if left == 0 {
            return;
        }
        tokio::select! {
            msg = sub.recv() => match msg {
                Some(RelayMsg::Event(ev)) => {
                    let Some(inner) = weak.upgrade() else { return };
                    if seen.len() >= SEEN_MAX {
                        seen.clear();
                    }
                    if seen.insert(ev.id) && handle_wrap(&inner, &mailbox, &link, &ev) == Wrap::Full {
                        // Not lost: it is asked for again when a slot frees.
                        seen.remove(&ev.id);
                    }
                }
                Some(RelayMsg::Eose) => {}
                None => return,
            },
            // A slot freed on a full link: ask the mailbox again. The relay
            // sends what it holds; what was handled before is skipped.
            _ = requery.notified() => {
                sub = relay.subscribe(vec![mailbox_filter(&mailbox, created_at)]);
            }
            _ = tokio::time::sleep(Duration::from_secs(left.min(3600))) => {}
        }
    }
}

/// The hello verifier: the attestation must verify in full (signature, app
/// id, role, in date, for `signer`) and so bind exactly the seal's signer.
fn verifies(app_id: &str, att: &str, signer: &PublicKey, now: u64) -> bool {
    verify_attestation(app_id, att.as_bytes(), signer, now).is_ok()
}

/// What became of a wrap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wrap {
    /// Handled, queued or dropped for good.
    Done,
    /// A good hello dropped because the link was full.
    Full,
}

fn handle_wrap(inner: &Arc<Inner>, mailbox: &Keys, link: &FriendLink, ev: &Event) -> Wrap {
    let now = unix_now();
    let app = inner.cfg.app_id.as_str();
    let opened = match open_hello(mailbox, &inner.runtime_keys, link, ev, now, |a, k| {
        verifies(app, a, k, now)
    }) {
        Ok(o) => o,
        Err(e) => {
            log::debug!("[signet friend] dropped {}: {e}", ev.id);
            return Wrap::Done;
        }
    };
    if opened.sender == inner.runtime_keys.public_key() {
        return Wrap::Done;
    }
    let Ok(info) = verify_attestation(
        app,
        opened.hello.attestation.as_bytes(),
        &opened.sender,
        now,
    ) else {
        return Wrap::Done;
    };
    let mut st = inner.lock();
    if !st.accepting_invites() || st.persona == Some(info.persona) {
        return Wrap::Done;
    }
    if blocked_in(&block_view(&st), &info.persona) {
        return Wrap::Done;
    }
    let hash = link.hash();
    if !st.friends.live.iter().any(|l| l.link.hash() == hash) {
        return Wrap::Done; // cancelled while this was in flight
    }
    let f = &mut st.friends;
    let (signer, persona) = (opened.sender.to_bytes(), info.persona.to_bytes());
    // A Decline sticks to the sender (signer or persona) for this link.
    if f.declined
        .iter()
        .any(|d| d.link == hash && (d.signer == signer || d.persona == persona))
    {
        return Wrap::Done;
    }
    // Someone already added, writing again: they probably never got the reply.
    if let Some(a) = f
        .accepted
        .iter_mut()
        .find(|a| a.link == hash && a.signer == signer)
    {
        if !a.wraps.contains(&ev.id.to_bytes())
            && now >= a.last_reply.saturating_add(RESEND_EVERY_SECS)
        {
            let relays = clean_inbox_relays(&opened.hello.relays);
            if !relays.is_empty() {
                a.last_reply = now;
                let owed = Owed {
                    to: opened.sender,
                    relays,
                    link: hash,
                    exp: link.exp,
                };
                f.add_owed(owed.clone());
                inner.save_friends(&st);
                drop(st);
                let inner = inner.clone();
                runtime().spawn(async move {
                    if let Err(e) = deliver_owed(&inner, &owed).await {
                        log::debug!("[signet friend] reply resend: {e}");
                    }
                });
            }
        }
        return Wrap::Done;
    }
    if f.handled.contains(&opened.id) || f.hellos.iter().any(|h| h.id == opened.id) {
        return Wrap::Done;
    }
    if f.hellos.iter().filter(|h| h.link == hash).count() >= MAX_HELLOS_PER_LINK {
        log::debug!("[signet friend] link full; dropped a hello");
        f.capped.insert(hash);
        return Wrap::Full;
    }
    // One link-holder with one valid persona must not fill the link.
    let from_sender = f
        .hellos
        .iter()
        .filter(|h| h.link == hash && h.opened.sender == opened.sender)
        .count();
    if from_sender >= MAX_HELLOS_PER_SENDER {
        log::debug!("[signet friend] sender already has {from_sender} waiting; dropped a hello");
        return Wrap::Done;
    }
    f.hellos.push(Waiting {
        id: opened.id,
        wrap: ev.id.to_bytes(),
        link: hash,
        link_exp: link.exp,
        persona: info.persona,
        opened,
    });
    Wrap::Done
}

// ─── Owed replies ───────────────────────────────────────────────────────────

impl FriendState {
    /// Remember a reply to send (one per recipient and link).
    fn add_owed(&mut self, o: Owed) {
        self.owed.retain(|x| !(x.to == o.to && x.link == o.link));
        self.owed.push(o);
        Self::cap(&mut self.owed, MAX_OWED);
    }
}

/// Build and publish one owed reply with the current name, relays and
/// attestation, and forget it once it is out. A failure leaves it stored.
async fn deliver_owed(inner: &Arc<Inner>, o: &Owed) -> Result<(), String> {
    let me = Signet {
        inner: inner.clone(),
    };
    let Some(att) = me.attestation_json() else {
        return Err("Added, but your My Signet link has expired, so they weren't told yet.".into());
    };
    let name = me.friend_name().unwrap_or_default();
    let reply = Reply::new(o.link, &name, me.inbox_relays(), att)
        .map_err(|e| format!("Added, but the reply failed: {e}"))?;
    let content = reply
        .to_json()
        .map_err(|e| format!("Added, but the reply failed: {e}"))?;
    let exp = o.exp.max(unix_now() + 60);
    let rumor = EventBuilder::new(Kind::Custom(FRIEND_REPLY_RUMOR_KIND), content)
        .tag(expiration_tag(exp))
        .build(inner.runtime_keys.public_key());
    let wrap = EventBuilder::gift_wrap(&inner.runtime_keys, &o.to, rumor, [expiration_tag(exp)])
        .await
        .map_err(|_| "Added, but the reply could not be sealed.".to_string())?;
    let sent = inner
        .connector
        .connect(&o.relays)
        .publish_acked(&wrap)
        .wait(inner.cfg.fetch_timeout)
        .await;
    if !sent.succeeded() {
        return Err(
            "Added, but couldn't reach their relays to tell them. It will try again.".into(),
        );
    }
    let mut st = inner.lock();
    st.friends
        .owed
        .retain(|x| !(x.to == o.to && x.link == o.link));
    inner.save_friends(&st);
    Ok(())
}

// ─── The reply (the inbox's third acceptance case) ──────────────────────────

/// A wrap to our runtime key whose rumor is a friend reply. Accepted only when
/// the reply's attestation verifies and binds exactly the seal signer, that
/// signer is the `to` of one of our pending links, and the reply's `link` is
/// that link's hash. Then the sender goes into the book, the pending record
/// goes, and [`FriendEvent::Added`] is queued. Anything else is dropped.
pub(super) fn accept_reply(inner: &Inner, book: &PlayedWithBook, gift: UnwrappedGift, now: u64) {
    let rumor = gift.rumor;
    if rumor.kind != Kind::Custom(FRIEND_REPLY_RUMOR_KIND) || rumor.pubkey != gift.sender {
        return;
    }
    let Ok(reply) = Reply::from_json(&rumor.content) else {
        return;
    };
    let app = inner.cfg.app_id.as_str();
    let Ok(info) = verify_attestation(app, reply.attestation.as_bytes(), &gift.sender, now) else {
        return;
    };
    {
        let st = inner.lock();
        if !st.accepting_invites()
            || st.persona != Some(book.owner())
            || info.persona == book.owner()
            || blocked_in(&block_view(&st), &info.persona)
        {
            return;
        }
        let waiting = st
            .friends
            .pending
            .iter()
            .any(|p| p.to == gift.sender && p.link == reply.link && p.exp > now);
        if !waiting {
            log::debug!("[signet friend] reply without a pending link; dropped");
            return;
        }
    }
    let entry = match book.record_link(
        &reply.attestation,
        &gift.sender,
        &reply.name,
        &reply.relays,
        now,
    ) {
        Ok(e) => e,
        Err(e) => {
            log::debug!("[signet friend] could not record a reply: {e}");
            return;
        }
    };
    let name = if entry.name.is_empty() {
        short_npub(&info.persona)
    } else {
        entry.name
    };
    let mut st = inner.lock();
    st.friends
        .pending
        .retain(|p| !(p.to == gift.sender && p.link == reply.link));
    st.friends.events.push_back(FriendEvent::Added {
        name,
        persona: info.persona,
    });
    inner.save_friends(&st);
}

// ─── The public API ─────────────────────────────────────────────────────────

impl Signet {
    /// Start the listeners for the links kept from an earlier run.
    pub(super) fn start_friend_listeners(&self) {
        let live: Vec<LiveFriendLink> = {
            let mut st = self.state();
            let now = unix_now();
            if st.friends.prune(now) {
                self.inner.save_friends(&st);
            }
            st.friends.live.clone()
        };
        for l in live {
            if let Some(h) = spawn_listener(&self.inner, &l) {
                self.state().friends.listeners.insert(l.link.hash(), h);
            }
        }
        self.retry_owed_replies();
    }

    /// Send the replies still owed from an earlier run (the publish failed, or
    /// the app was closed first). Whatever fails stays stored for the next
    /// launch; a reply lapses with its link.
    fn retry_owed_replies(&self) {
        let owed: Vec<Owed> = self.state().friends.owed.clone();
        if owed.is_empty() {
            return;
        }
        let inner = self.inner.clone();
        runtime().spawn(async move {
            for o in owed {
                if let Err(e) = deliver_owed(&inner, &o).await {
                    log::debug!("[signet friend] owed reply not sent: {e}");
                }
            }
        });
    }

    /// The name this install puts in a hello or a reply: the persona's name
    /// cut to 32 characters, or `None` when signed out or it has none.
    pub fn friend_name(&self) -> Option<String> {
        let n: String = self.display_name()?.chars().take(NAME_CHARS).collect();
        let n = sanitise_name(&n);
        (!n.is_empty()).then_some(n)
    }

    /// Make a friend link to this install: `to` is the runtime key, the relays
    /// are the inbox relays, it lasts seven days. Starts its mailbox listener.
    /// At most [`MAX_LIVE_LINKS`] at once. Needs a signed-in persona.
    pub fn create_friend_link(&self) -> Result<FriendLink, String> {
        let now = unix_now();
        let relays = self.inbox_relays();
        if relays.is_empty() {
            return Err("no inbox relays to put in the link".into());
        }
        let live = {
            let mut st = self.state();
            if !st.accepting_invites() {
                return Err("sign in with My Signet first".into());
            }
            if st.friends.prune(now) {
                self.inner.save_friends(&st);
            }
            if st.friends.live.len() >= MAX_LIVE_LINKS {
                return Err(format!(
                    "You already have {MAX_LIVE_LINKS} friend links. Cancel one first."
                ));
            }
            let link = FriendLink::new(
                self.runtime_pubkey(),
                relays,
                &self.inner.cfg.app_id,
                now,
                LINK_TTL_DEFAULT,
            )
            .map_err(|e| e.to_string())?;
            let live = LiveFriendLink {
                link,
                created_at: now,
            };
            st.friends.live.push(live.clone());
            self.inner.save_friends(&st);
            live
        };
        // The listener opens its connection outside the state lock.
        match spawn_listener(&self.inner, &live) {
            Some(h) => {
                self.state().friends.listeners.insert(live.link.hash(), h);
                Ok(live.link)
            }
            None => {
                let hash = live.link.hash();
                self.cancel_friend_link(&hash);
                Err("could not open the link's mailbox".into())
            }
        }
    }

    /// Your live links (not lapsed), oldest first.
    pub fn friend_links(&self) -> Vec<LiveFriendLink> {
        let mut st = self.state();
        if st.friends.prune(unix_now()) {
            self.inner.save_friends(&st);
        }
        st.friends.live.clone()
    }

    /// Stop listening on a link (by [`FriendLink::hash`]). The hellos waiting
    /// on it go with it (they are kept in memory only, so a restart would
    /// have dropped them anyway); replies already owed to people you added
    /// are still sent. `false` if there was no such link.
    pub fn cancel_friend_link(&self, hash: &[u8; 32]) -> bool {
        let mut st = self.state();
        let before = st.friends.live.len();
        st.friends.live.retain(|l| l.link.hash() != *hash);
        if let Some(l) = st.friends.listeners.remove(hash) {
            l.abort.abort();
        }
        st.friends.hellos.retain(|h| h.link != *hash);
        st.friends.capped.remove(hash);
        let gone = st.friends.live.len() != before;
        if gone {
            self.inner.save_friends(&st);
        }
        gone
    }

    /// How many live links were dropped when this `Signet` opened, because the
    /// file was for another persona or runtime key.
    pub fn friend_links_dropped_at_open(&self) -> usize {
        self.state().friends.dropped_at_open
    }

    /// People who used one of your links and wait for your tap, oldest first.
    ///
    /// Each carries the attested persona (`persona`) so the app can say who it
    /// is: a My Signet contact by label and tier, anyone else by short npub.
    /// The `name` is the sender's own claim. A hello whose link has lapsed is
    /// not listed.
    pub fn friend_hellos(&self) -> Vec<FriendHello> {
        let mut st = self.state();
        if !st.accepting_invites() {
            return Vec::new();
        }
        if st.friends.prune(unix_now()) {
            self.inner.save_friends(&st);
        }
        st.friends
            .hellos
            .iter()
            .map(|w| FriendHello {
                id: hex::encode(w.id),
                name: w.opened.hello.name.clone(),
                link: hex::encode(w.link),
                persona: w.persona,
                runtime: w.opened.sender,
            })
            .collect()
    }

    /// Add the person behind a waiting hello: they go in the played-with book
    /// (with no game counted) and a friend reply (a gift wrap with its own
    /// rumor kind, carrying the link hash, your name, your inbox relays and
    /// your attestation) goes to their runtime key on the relays their hello
    /// named.
    ///
    /// Refused once the link has expired or been cancelled, or when the
    /// sender has been blocked since. The reply is stored before it is sent,
    /// and kept (and retried at every launch, until the link would have
    /// lapsed) if it cannot be published.
    ///
    /// `Ok` carries the new book entry once the reply is published. `Err` may
    /// mean the person was added but the reply did not go out (the text says
    /// so); the book shows which.
    pub fn accept_hello(&self, id: &str) -> Task<Result<PlayedWithEntry, String>> {
        self.accept_hello_at(id, unix_now())
    }

    /// [`Signet::accept_hello`] at a given time (tests of the expiry rule).
    #[doc(hidden)]
    pub fn accept_hello_at(&self, id: &str, now: u64) -> Task<Result<PlayedWithEntry, String>> {
        if self.attestation_json().is_none() {
            let msg = if self.attestation().is_some() {
                "Your My Signet link has expired; refresh it first."
            } else {
                "sign in with My Signet first"
            };
            return Task::ready(Err(msg.into()));
        }
        let (w, book) = {
            let mut st = self.state();
            let found = st
                .friends
                .hellos
                .iter()
                .find(|w| hex::encode(w.id) == id)
                .cloned();
            let (Some(w), Some(book)) = (found, st.book.clone()) else {
                return Task::ready(Err("That friend request is gone.".into()));
            };
            if !st.accepting_invites() {
                return Task::ready(Err("That friend request is gone.".into()));
            }
            let live = st.friends.live.iter().any(|l| l.link.hash() == w.link);
            let refusal = if w.link_exp <= now {
                Some("That friend link has expired.")
            } else if !live {
                Some("That friend link was cancelled.")
            } else if blocked_in(&block_view(&st), &w.persona) {
                Some("You have blocked them.")
            } else {
                None
            };
            if let Some(msg) = refusal {
                st.friends.hellos.retain(|x| x.id != w.id);
                self.inner.save_friends(&st);
                return Task::ready(Err(msg.into()));
            }
            (w, book)
        };
        let h = &w.opened.hello;
        let entry =
            match book.record_link(&h.attestation, &w.opened.sender, &h.name, &h.relays, now) {
                Ok(e) => e,
                // The row stays, so the reason is not lost; Decline clears it.
                Err(e) => return Task::ready(Err(format!("couldn't add them: {e}"))),
            };
        let relays = clean_inbox_relays(&h.relays);
        let owed = Owed {
            to: w.opened.sender,
            relays: relays.clone(),
            link: w.link,
            exp: w.link_exp,
        };
        {
            let mut st = self.state();
            let f = &mut st.friends;
            // This sender's other waiting hellos on the link are answered too.
            let mut gone = vec![w.id];
            let mut wraps = vec![w.wrap];
            f.hellos.retain(|x| {
                let same = x.link == w.link && x.opened.sender == w.opened.sender;
                if same {
                    gone.push(x.id);
                    wraps.push(x.wrap);
                }
                !same
            });
            for g in gone {
                f.mark_handled(g);
            }
            f.accepted
                .retain(|a| !(a.link == w.link && a.signer == w.opened.sender.to_bytes()));
            f.accepted.push(Accepted {
                link: w.link,
                signer: w.opened.sender.to_bytes(),
                exp: w.link_exp,
                last_reply: now,
                wraps,
            });
            FriendState::cap(&mut f.accepted, MAX_ACCEPTED);
            if !relays.is_empty() {
                f.add_owed(owed.clone());
            }
            f.requery_if_room(&w.link);
            self.inner.save_friends(&st);
        }
        if relays.is_empty() {
            return Task::ready(Err(
                "Added, but they shared no relays to tell them on.".into()
            ));
        }
        let inner = self.inner.clone();
        Task::spawn(async move { deliver_owed(&inner, &owed).await.map(|()| entry) })
    }

    /// Turn a waiting hello down. Nothing is sent. The sender (the seal
    /// signer and the attested persona) is remembered until the link lapses:
    /// their later hellos on this link are dropped silently, and their other
    /// waiting hellos go now. `false` if there was no such hello.
    pub fn decline_hello(&self, id: &str) -> bool {
        let mut st = self.state();
        let Some(w) = st
            .friends
            .hellos
            .iter()
            .find(|w| hex::encode(w.id) == id)
            .cloned()
        else {
            return false;
        };
        let f = &mut st.friends;
        let (signer, persona) = (w.opened.sender.to_bytes(), w.persona.to_bytes());
        let mut gone = vec![w.id];
        f.hellos.retain(|x| {
            let same = x.link == w.link
                && (x.opened.sender.to_bytes() == signer || x.persona.to_bytes() == persona);
            if same {
                gone.push(x.id);
            }
            !same
        });
        for g in gone {
            f.mark_handled(g);
        }
        f.declined.push(Declined {
            link: w.link,
            signer,
            persona,
            exp: w.link_exp,
        });
        FriendState::cap(&mut f.declined, MAX_DECLINED);
        f.requery_if_room(&w.link);
        self.inner.save_friends(&st);
        true
    }

    /// Use someone's friend link: send them a hello (your name, inbox relays
    /// and attestation, sealed by your runtime key, readable only by the link's
    /// owner) on the link's relays, and wait for their reply. Refuses a link to
    /// your own runtime key and one that has lapsed.
    pub fn use_friend_link(&self, link: &FriendLink) -> Task<Result<(), String>> {
        let now = unix_now();
        if link.to == self.runtime_pubkey() {
            return Task::ready(Err("That's your own friend link.".into()));
        }
        if link.exp <= now {
            return Task::ready(Err("That friend link has expired.".into()));
        }
        let link_relays = usable_link_relays(link);
        if link_relays.is_empty() {
            return Task::ready(Err("That friend link names no relay this phone can use.".into()));
        }
        let Some(att) = self.attestation_json() else {
            let msg = if self.attestation().is_some() {
                "Your My Signet link has expired; refresh it first."
            } else {
                "sign in with My Signet first"
            };
            return Task::ready(Err(msg.into()));
        };
        let relays = self.inbox_relays();
        if relays.is_empty() {
            return Task::ready(Err("no inbox relays to put in your hello".into()));
        }
        if !self.state().accepting_invites() {
            return Task::ready(Err("sign in with My Signet first".into()));
        }
        let name = self.friend_name().unwrap_or_default();
        let hash = link.hash();
        let ev = Hello::new(hash, &name, relays, att)
            .and_then(|h| {
                seal_hello(
                    &self.inner.runtime_keys,
                    link,
                    &h,
                    &self.inner.cfg.app_id,
                    now,
                )
            })
            .map_err(|e| e.to_string());
        let ev = match ev {
            Ok(ev) => ev,
            Err(e) => return Task::ready(Err(e)),
        };
        let previous = {
            let mut st = self.state();
            let p = &mut st.friends.pending;
            let previous = p.iter().find(|x| x.link == hash && x.exp > now).cloned();
            p.retain(|x| x.link != hash && x.exp > now);
            p.push(PendingFriendLink {
                to: link.to,
                link: hash,
                relays: link_relays.clone(),
                exp: link.exp,
            });
            let skip = p.len().saturating_sub(MAX_PENDING);
            p.drain(..skip);
            self.inner.save_friends(&st);
            previous
        };
        let inner = self.inner.clone();
        Task::spawn(async move {
            let sent = inner
                .connector
                .connect(&link_relays)
                .publish_acked(&ev)
                .wait(inner.cfg.fetch_timeout)
                .await;
            if sent.succeeded() {
                Ok(())
            } else {
                let mut st = inner.lock();
                st.friends.pending.retain(|x| x.link != hash);
                // An earlier hello on this link was delivered: keep waiting for it.
                st.friends.pending.extend(previous);
                inner.save_friends(&st);
                Err("couldn't reach their relays".to_string())
            }
        })
    }

    /// Links you used that have not been answered yet, oldest first. A record
    /// lapses with its link.
    pub fn pending_friend_links(&self) -> Vec<PendingFriendLink> {
        let mut st = self.state();
        if st.friends.prune(unix_now()) {
            self.inner.save_friends(&st);
        }
        st.friends.pending.clone()
    }

    /// What the friend flow has to tell the app, oldest first.
    pub fn take_friend_events(&self) -> Vec<FriendEvent> {
        self.state().friends.events.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_and_pending_records_lapse_with_their_expiry() {
        let me = Keys::generate().public_key();
        let link = FriendLink::new(me, vec!["wss://r.example".into()], "t", 1_000, 3_600).unwrap();
        let mut fs = FriendState::default();
        fs.live.push(LiveFriendLink {
            link: link.clone(),
            created_at: 1_000,
        });
        fs.pending.push(PendingFriendLink {
            to: me,
            link: link.hash(),
            relays: vec![],
            exp: link.exp,
        });
        assert!(!fs.prune(link.exp - 1));
        assert_eq!((fs.live.len(), fs.pending.len()), (1, 1));
        assert!(fs.prune(link.exp));
        assert_eq!((fs.live.len(), fs.pending.len()), (0, 0));
    }

    #[test]
    fn handled_ids_are_bounded_oldest_first() {
        let mut fs = FriendState::default();
        for i in 0..(MAX_HANDLED + 5) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            fs.mark_handled(id);
        }
        assert_eq!(fs.handled.len(), MAX_HANDLED);
        assert_eq!(
            u64::from_le_bytes(fs.handled[0][..8].try_into().unwrap()),
            5
        );
    }
}
