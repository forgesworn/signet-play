//! Talking to Nostr relays, behind a trait so every flow above it runs against
//! an in-memory fake in tests.
//!
//! - [`Relay`]: publish an event to a set of relays, or open a subscription
//!   (stored matches, then [`RelayMsg::Eose`] once per relay, then live ones).
//! - [`Connector`]: turns a list of relay URLs into a [`Relay`]. The live one is
//!   [`WsConnector`] (one websocket worker per URL on the crate runtime,
//!   reconnecting with backoff); the fake is [`FakeNetwork`] (one in-memory
//!   [`FakeRelayHub`] per URL, with real stored / replaceable / addressable /
//!   ephemeral / NIP-09 / NIP-40 semantics).
//!
//! This layer is a pipe, not a gate: nothing it hands out is trusted until the
//! module above has verified it. It does drop events whose id or signature
//! does not verify.
//!
//! Relay order, health, backoff and the defaults fallback live in the shared
//! [`RelayPool`] (`decented-relays`): a worker dials a relay only when the
//! pool says it may, and reports every connect, failure and response time
//! back. Reads go to every relay that is not backed off, at once; writes go
//! to the top healthy relays in the player's order, also at once. NIP-46
//! requests reach every approved transport relay: the signer may listen on
//! any one of them, independently of content-write health ranking.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use decented_relays::RelayPool;
use futures_util::{SinkExt, StreamExt};
use nostr::filter::MatchEventOptions;
use nostr::{Event, EventBuilder, Filter, Keys, Kind, RelayUrl};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::unix_now;

/// One thing a subscription yields.
#[derive(Debug, Clone)]
pub enum RelayMsg {
    Event(Box<Event>),
    /// One relay has sent everything it had stored (or could not be reached).
    Eose,
}

/// Where one subscription stands on its relay. Read it with
/// [`Subscription::status`]; only meaningful when the subscription spans a
/// single relay (the sign-in opens one connection per candidate relay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubStatus {
    /// Dialling, or waiting for a backed-off relay to be dialled again.
    Connecting,
    /// Connected (the REQ is out or about to go).
    Up,
    /// Could not connect, or the connection dropped. Short, secret-free
    /// reason (e.g. `HTTP error: 503 Service Unavailable`). The relay layer
    /// dials again by itself; [`SubStatus::Up`] follows if that works.
    Down(String),
    /// The relay answered the REQ with CLOSED. The text is the relay's own.
    /// Nothing more will arrive on this subscription.
    Closed(String),
}

/// Bound on received-but-unread messages per subscription: a flooding relay
/// drops, never grows.
pub const SUB_QUEUE: usize = 1024;

/// Each live relay's own share of a subscription, in front of the shared
/// queue: a relay that floods overflows its share, never the others'.
const RELAY_QUEUE: usize = 256;

type CloseFn = Box<dyn FnOnce() + Send>;

/// A live subscription. Dropping it closes it on every relay.
pub struct Subscription {
    rx: mpsc::Receiver<RelayMsg>,
    relays: usize,
    close: Option<CloseFn>,
    /// How many relays answered with a made-up [`RelayMsg::Eose`] because
    /// they could not be reached (a failed dial, a dropped connection).
    down: Arc<AtomicUsize>,
    status: watch::Receiver<SubStatus>,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription").field("relays", &self.relays).finish()
    }
}

impl Subscription {
    pub fn new(rx: mpsc::Receiver<RelayMsg>, relays: usize, close: Option<CloseFn>) -> Self {
        // A layer that never reports a status reads as connected.
        let (_tx, status) = watch::channel(SubStatus::Up);
        Subscription { rx, relays, close, down: Arc::new(AtomicUsize::new(0)), status }
    }

    /// Follow the status the relay layer reports (see [`SubStatus`]).
    pub fn with_status(mut self, status: watch::Receiver<SubStatus>) -> Self {
        self.status = status;
        self
    }

    /// Where this subscription stands now.
    pub fn status(&self) -> SubStatus {
        self.status.borrow().clone()
    }

    /// A handle that wakes on every status change, for use beside
    /// [`Subscription::recv`] in a `select!`.
    pub fn status_watch(&self) -> watch::Receiver<SubStatus> {
        self.status.clone()
    }

    /// Share the counter the relay layer bumps when it answers for a relay it
    /// could not reach. Without it every relay reads as reachable.
    pub fn with_unreachable_counter(mut self, down: Arc<AtomicUsize>) -> Self {
        self.down = down;
        self
    }

    /// How many of this subscription's relays could not be reached: they
    /// ended with an [`RelayMsg::Eose`] that was not theirs. A relay that is
    /// connected but silent is **not** counted.
    pub fn unreachable(&self) -> usize {
        self.down.load(Ordering::Relaxed)
    }

    /// How many relays this subscription spans (= how many EOSEs to expect).
    pub fn relays(&self) -> usize {
        self.relays
    }

    pub async fn recv(&mut self) -> Option<RelayMsg> {
        self.rx.recv().await
    }

    pub fn try_recv(&mut self) -> Option<RelayMsg> {
        self.rx.try_recv().ok()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(close) = self.close.take() {
            close();
        }
    }
}

/// What a write to a set of relays came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublishReport {
    /// Relays the event was sent to.
    pub targets: usize,
    /// Relays that answered OK (accepted it).
    pub ok: usize,
    /// Relays that answered "not accepted".
    pub refused: usize,
}

impl PublishReport {
    /// A write counts as done when at least one relay took it.
    pub fn succeeded(&self) -> bool {
        self.ok >= 1
    }

    /// Relays that said nothing: down, dropped, or too slow.
    pub fn silent(&self) -> usize {
        self.targets.saturating_sub(self.ok + self.refused)
    }
}

/// The answers to one publish, as they arrive. Dropping it is fine: the
/// publish itself does not depend on anyone waiting.
pub struct PublishAck {
    rx: mpsc::UnboundedReceiver<bool>,
    targets: usize,
}

impl PublishAck {
    pub fn new(rx: mpsc::UnboundedReceiver<bool>, targets: usize) -> Self {
        PublishAck { rx, targets }
    }

    /// An ack for a relay layer that cannot tell (nothing to wait for).
    pub fn unknown() -> Self {
        let (_tx, rx) = mpsc::unbounded_channel();
        PublishAck { rx, targets: 0 }
    }

    /// Wait for every target to answer, or for `timeout`. Returns early once
    /// every relay that could still answer has answered or given up.
    pub async fn wait(mut self, timeout: Duration) -> PublishReport {
        let mut r = PublishReport { targets: self.targets, ok: 0, refused: 0 };
        let deadline = tokio::time::Instant::now() + timeout;
        while r.ok + r.refused < self.targets {
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Some(true)) => r.ok += 1,
                Ok(Some(false)) => r.refused += 1,
                // Every sender is gone (each remaining relay gave up) or time is up.
                Ok(None) | Err(_) => break,
            }
        }
        r
    }
}

pub trait Relay: Send + Sync {
    /// Send `ev` to the chosen relays (queued for a relay that is still connecting).
    fn publish(&self, ev: &Event);
    /// [`Relay::publish`], and a handle on the relays' answers. A write is done
    /// when at least one relay answers OK ([`PublishReport::succeeded`]).
    fn publish_acked(&self, ev: &Event) -> PublishAck {
        self.publish(ev);
        PublishAck::unknown()
    }
    /// Open a subscription. Registration happens before this returns, so an
    /// event published after it is never missed.
    fn subscribe(&self, filters: Vec<Filter>) -> Subscription;
    /// The URLs this set talks to, in the player's order.
    fn urls(&self) -> Vec<String>;
    /// Whether another [`Relay::subscribe`] would also ask the built-in
    /// defaults (every listed relay is failing and a fallback is allowed).
    fn fallback_ready(&self) -> bool {
        false
    }
    /// Dial again now: end any backoff wait at once, and drop a live
    /// connection for a fresh one (after a stretch in the background, Android
    /// cuts the network and a socket can look up long after it is dead).
    /// Standing subscriptions are sent again on the new connection. The
    /// in-memory fake has nothing to redial.
    fn reconnect(&self) {}
}

pub trait Connector: Send + Sync {
    fn connect(&self, urls: &[String]) -> Arc<dyn Relay>;
    /// The player's own relay list (Settings): same as [`Connector::connect`],
    /// but the built-in defaults stand in when every listed relay is down.
    fn connect_main(&self, urls: &[String]) -> Arc<dyn Relay> {
        self.connect(urls)
    }
}

/// What a read of the relays found, and how many of them really answered.
#[derive(Debug, Clone, Default)]
pub struct FetchReport {
    /// Stored events matching the filters, deduplicated by id, newest first.
    pub events: Vec<Event>,
    /// Relays that answered (sent EOSE themselves, or sent an event).
    pub answered: usize,
    /// Relays asked.
    pub total: usize,
}

impl FetchReport {
    /// At least one relay answered. With no events, the answer was "nothing
    /// published"; without it, the relays could not be reached.
    pub fn reached(&self) -> bool {
        self.answered > 0
    }
}

/// Stored events matching `filters`, deduplicated by id, newest first. Returns
/// when every relay has sent EOSE (or failed), or at `timeout`.
pub async fn fetch(relay: &dyn Relay, filters: Vec<Filter>, timeout: Duration) -> Vec<Event> {
    fetch_report(relay, filters, timeout).await.events
}

/// [`fetch`], and how many relays answered. When none did and the built-in
/// defaults may stand in, asks them once.
pub async fn fetch_report(relay: &dyn Relay, filters: Vec<Filter>, timeout: Duration) -> FetchReport {
    let listed = relay.urls().len();
    let (first, _) = fetch_round(relay, filters.clone(), timeout, &|_| false).await;
    if first.reached() || first.total > listed || !relay.fallback_ready() {
        return first;
    }
    // Nobody answered, and the pool now knows it: the defaults get a turn.
    fetch_round(relay, filters, timeout, &|_| false).await.0
}

/// [`fetch`] on a set of one relay, for a caller that must tell "holds
/// nothing" from "would not say": a relay that answered the REQ with CLOSED
/// does not count as having answered.
pub(crate) async fn fetch_unless_refused(relay: &dyn Relay, filters: Vec<Filter>, timeout: Duration) -> FetchReport {
    let (mut report, refused) = fetch_round(relay, filters, timeout, &|_| false).await;
    if refused {
        report.answered = 0;
    }
    report
}

/// [`fetch`] for a feature that needs only the first valid answer: returns as
/// soon as an event `accept` likes arrives, without waiting for slow relays.
pub async fn fetch_first(
    relay: &dyn Relay,
    filters: Vec<Filter>,
    timeout: Duration,
    accept: impl Fn(&Event) -> bool + Sync,
) -> FetchReport {
    fetch_round(relay, filters, timeout, &accept).await.0
}

/// One read, and whether an EOSE came from a relay that had CLOSED the request.
async fn fetch_round(relay: &dyn Relay, filters: Vec<Filter>, timeout: Duration, early: &(dyn Fn(&Event) -> bool + Sync)) -> (FetchReport, bool) {
    // What one relay may send past its filters' limits is dropped in its own
    // worker (`WorkerSub::cap`), so a flooding relay cannot end the read
    // before the others answer.
    let mut sub = relay.subscribe(filters);
    let want = sub.relays();
    let (mut eose, mut refused) = (0, false);
    let mut out: Vec<Event> = Vec::new();
    let mut seen: std::collections::HashSet<nostr::EventId> = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while eose < want {
        match tokio::time::timeout_at(deadline, sub.recv()).await {
            Ok(Some(RelayMsg::Event(ev))) => {
                if seen.insert(ev.id) {
                    let stop = early(&ev);
                    out.push(*ev);
                    if stop {
                        break;
                    }
                }
            }
            Ok(Some(RelayMsg::Eose)) => {
                // The status is set before the EOSE goes out, so a CLOSED shows here.
                refused |= matches!(sub.status(), SubStatus::Closed(_));
                eose += 1;
            }
            Ok(None) | Err(_) => break,
        }
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    let answered = eose.saturating_sub(sub.unreachable()).max(usize::from(!out.is_empty()));
    (FetchReport { events: out, answered, total: want }, refused)
}

/// A one-shot read of stored events from live relays, on the crate's runtime:
/// connect to `urls` (in the given order, all at once), [`fetch_report`], hang
/// up. For callers outside this crate that have no runtime of their own (the
/// app's update check). The report says whether any relay answered, so "nothing
/// published" and "could not reach the relays" stay different.
pub fn fetch_live(urls: Vec<String>, filters: Vec<Filter>, timeout: Duration) -> crate::Task<FetchReport> {
    crate::Task::spawn(async move {
        let set = WsRelaySet::start_in(RelayPool::global(), &urls, true);
        fetch_report(&set, filters, timeout).await
    })
}

fn event_ok(ev: &Event) -> bool {
    ev.verify().is_ok()
}

fn expiration(ev: &Event) -> Option<u64> {
    ev.tags.iter().find_map(|t| {
        let s = t.as_slice();
        (s.len() >= 2 && s[0] == "expiration").then(|| s[1].parse::<u64>().ok()).flatten()
    })
}

fn is_expired(ev: &Event, now: u64) -> bool {
    expiration(ev).is_some_and(|x| x <= now)
}

fn matches_any(filters: &[Filter], ev: &Event) -> bool {
    filters.iter().any(|f| f.match_event(ev, MatchEventOptions::new()))
}

// ─── In-memory fake ─────────────────────────────────────────────────────────

struct HubSub {
    filters: Vec<Filter>,
    tx: mpsc::Sender<RelayMsg>,
    status: Arc<watch::Sender<SubStatus>>,
}

/// One REQ a [`FakeRelayHub`] received: on which connection, and what it asked.
#[derive(Debug, Clone)]
pub struct FakeReq {
    /// The connection ([`Connector::connect`] call) the REQ came in on. Each
    /// call makes a new one, as each live [`WsRelaySet`] has its own sockets.
    pub connection: u64,
    pub filters: Vec<Filter>,
}

#[derive(Default)]
struct HubState {
    stored: Vec<Event>,
    published: Vec<Event>,
    subs: HashMap<u64, HubSub>,
    next: u64,
    offline: bool,
    /// Why an offline relay is down (the dial error), if a test says.
    offline_reason: Option<String>,
    refusing: bool,
    /// Answer every REQ with CLOSED and this text.
    closing: Option<String>,
    /// Take the REQ but never send EOSE.
    mute: bool,
    reqs: Vec<FakeReq>,
}

/// One in-memory relay. Cheap to clone (shared state).
#[derive(Clone, Default)]
pub struct FakeRelayHub {
    inner: Arc<Mutex<HubState>>,
}

impl FakeRelayHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept an event as a relay would. `false` = refused (bad signature,
    /// already expired, older than the replaceable version held, or offline).
    pub fn publish(&self, ev: &Event) -> bool {
        if !event_ok(ev) {
            return false;
        }
        let now = unix_now();
        let Ok(mut g) = self.inner.lock() else { return false };
        if g.offline || g.refusing || is_expired(ev, now) {
            return false;
        }
        g.published.push(ev.clone());
        let kind = ev.kind;
        if kind == Kind::EventDeletion {
            apply_deletion(&mut g.stored, ev);
            g.stored.push(ev.clone());
        } else if kind.is_ephemeral() {
            // delivered, never stored
        } else if kind.is_replaceable() || kind.is_addressable() {
            let d = ev.tags.identifier().unwrap_or("").to_string();
            let same = |e: &Event| {
                e.pubkey == ev.pubkey
                    && e.kind == kind
                    && (!kind.is_addressable() || e.tags.identifier().unwrap_or("") == d)
            };
            if g.stored.iter().any(|e| same(e) && e.created_at > ev.created_at) {
                return false;
            }
            g.stored.retain(|e| !same(e));
            g.stored.push(ev.clone());
        } else {
            if g.stored.iter().any(|e| e.id == ev.id) {
                return true;
            }
            g.stored.push(ev.clone());
        }
        let mut dead = Vec::new();
        for (id, s) in &g.subs {
            if matches_any(&s.filters, ev)
                && let Err(mpsc::error::TrySendError::Closed(_)) = s.tx.try_send(RelayMsg::Event(Box::new(ev.clone())))
            {
                dead.push(*id);
            }
        }
        for id in dead {
            g.subs.remove(&id);
        }
        true
    }

    /// Stored events matching `filters` (expired ones hidden), newest first,
    /// each filter's `limit` applied.
    pub fn query(&self, filters: &[Filter]) -> Vec<Event> {
        let now = unix_now();
        let Ok(g) = self.inner.lock() else { return Vec::new() };
        let mut out: Vec<Event> = Vec::new();
        for f in filters {
            let mut hits: Vec<&Event> = g
                .stored
                .iter()
                .filter(|e| !is_expired(e, now) && f.match_event(e, MatchEventOptions::new()))
                .collect();
            hits.sort_by_key(|e| std::cmp::Reverse(e.created_at));
            if let Some(limit) = f.limit {
                hits.truncate(limit);
            }
            for e in hits {
                if !out.iter().any(|o| o.id == e.id) {
                    out.push(e.clone());
                }
            }
        }
        out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        out
    }

    /// Everything currently stored (tests inspect this).
    pub fn stored(&self) -> Vec<Event> {
        self.inner.lock().map(|g| g.stored.clone()).unwrap_or_default()
    }

    /// Every event ever accepted, ephemeral ones included.
    pub fn published(&self) -> Vec<Event> {
        self.inner.lock().map(|g| g.published.clone()).unwrap_or_default()
    }

    /// An offline relay refuses publishes and answers every REQ with an
    /// immediate EOSE and nothing else (as a failed dial does).
    pub fn set_offline(&self, offline: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.offline = offline;
        }
    }

    /// [`FakeRelayHub::set_offline`] with the reason a dial would give
    /// (e.g. `HTTP error: 503 Service Unavailable`).
    pub fn set_failing(&self, reason: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.offline = true;
            g.offline_reason = Some(reason.to_string());
        }
    }

    /// `Some(text)`: every REQ is answered with CLOSED and that text (a relay
    /// that refuses the read). `None` turns it off.
    pub fn set_closing(&self, text: Option<&str>) {
        if let Ok(mut g) = self.inner.lock() {
            g.closing = text.map(str::to_string);
        }
    }

    /// A muted relay is connected and takes every REQ, but never sends EOSE.
    pub fn set_mute(&self, mute: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.mute = mute;
        }
    }

    /// CLOSE every open subscription from the relay's side, with `text`.
    pub fn close_all(&self, text: &str) {
        if let Ok(mut g) = self.inner.lock() {
            for (_, s) in g.subs.drain() {
                s.status.send_replace(SubStatus::Closed(text.to_string()));
            }
        }
    }

    /// The connection drops under every open subscription (they stay
    /// registered, as a reconnecting socket keeps them): status goes `Down`.
    pub fn drop_connections(&self, reason: &str) {
        if let Ok(g) = self.inner.lock() {
            for s in g.subs.values() {
                s.status.send_replace(SubStatus::Down(reason.to_string()));
            }
        }
    }

    /// A refusing relay is reachable (it answers every REQ) but takes no
    /// publishes: one that says no, or never acks.
    pub fn set_refusing(&self, refusing: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.refusing = refusing;
        }
    }

    /// Whether the relay is switched off ([`FakeRelayHub::set_offline`]).
    pub fn is_offline(&self) -> bool {
        self.inner.lock().map(|g| g.offline).unwrap_or(false)
    }

    /// Every REQ this relay has been asked, with the connection it came in on
    /// (tests check which purposes share a connection).
    pub fn reqs(&self) -> Vec<FakeReq> {
        self.inner.lock().map(|g| g.reqs.clone()).unwrap_or_default()
    }

    /// Live subscriptions currently open (tests check that drops close them).
    pub fn open_subscriptions(&self) -> usize {
        self.inner.lock().map(|g| g.subs.values().filter(|s| !s.tx.is_closed()).count()).unwrap_or(0)
    }

    fn open(
        &self,
        connection: u64,
        filters: Vec<Filter>,
        tx: mpsc::Sender<RelayMsg>,
        status: Arc<watch::Sender<SubStatus>>,
    ) -> Option<u64> {
        let stored = self.query(&filters);
        let mut g = self.inner.lock().ok()?;
        g.reqs.push(FakeReq { connection, filters: filters.clone() });
        // The status goes first, as in the live worker: whoever sees the
        // EOSE already knows whether it was the relay's own.
        if g.offline {
            let why = g.offline_reason.clone().unwrap_or_else(|| "could not connect".into());
            status.send_replace(SubStatus::Down(why));
            let _ = tx.try_send(RelayMsg::Eose);
            return None;
        }
        status.send_replace(SubStatus::Up);
        if let Some(text) = g.closing.clone() {
            status.send_replace(SubStatus::Closed(text));
            let _ = tx.try_send(RelayMsg::Eose);
            return None;
        }
        for e in stored {
            let _ = tx.try_send(RelayMsg::Event(Box::new(e)));
        }
        if !g.mute {
            let _ = tx.try_send(RelayMsg::Eose);
        }
        let id = g.next;
        g.next += 1;
        g.subs.insert(id, HubSub { filters, tx, status });
        Some(id)
    }

    fn close(&self, id: u64) {
        if let Ok(mut g) = self.inner.lock() {
            g.subs.remove(&id);
        }
    }
}

/// NIP-09: drop the author's own events named by `e` ids or `a` coordinates
/// (`kind:pubkey:d`, versions up to the deletion's `created_at`).
fn apply_deletion(stored: &mut Vec<Event>, del: &Event) {
    let mut ids = Vec::new();
    let mut coords = Vec::new();
    for t in del.tags.iter() {
        let s = t.as_slice();
        if s.len() < 2 {
            continue;
        }
        match s[0].as_str() {
            "e" => ids.push(s[1].clone()),
            "a" => coords.push(s[1].clone()),
            _ => {}
        }
    }
    stored.retain(|e| {
        if e.pubkey != del.pubkey {
            return true;
        }
        if ids.iter().any(|i| *i == e.id.to_hex()) {
            return false;
        }
        let coord = format!("{}:{}:{}", e.kind.as_u16(), e.pubkey.to_hex(), e.tags.identifier().unwrap_or(""));
        !(coords.contains(&coord) && e.created_at <= del.created_at)
    });
}

/// A set of in-memory relays keyed by URL. Clones share the hubs.
#[derive(Clone, Default)]
pub struct FakeNetwork {
    hubs: Arc<Mutex<HashMap<String, FakeRelayHub>>>,
}

impl FakeNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    /// The hub behind `url` (created on first use).
    pub fn hub(&self, url: &str) -> FakeRelayHub {
        let mut g = self.hubs.lock().expect("fake network mutex");
        g.entry(url.trim_end_matches('/').to_string()).or_default().clone()
    }
}

impl Connector for FakeNetwork {
    fn connect(&self, urls: &[String]) -> Arc<dyn Relay> {
        let hubs = urls.iter().map(|u| self.hub(u)).collect();
        Arc::new(FakeRelaySet { hubs, urls: urls.to_vec(), connection: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed) })
    }
}

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

struct FakeRelaySet {
    hubs: Vec<FakeRelayHub>,
    urls: Vec<String>,
    connection: u64,
}

impl Relay for FakeRelaySet {
    fn publish(&self, ev: &Event) {
        for h in &self.hubs {
            h.publish(ev);
        }
    }

    fn publish_acked(&self, ev: &Event) -> PublishAck {
        let (tx, rx) = mpsc::unbounded_channel();
        for h in &self.hubs {
            // A relay that is offline says nothing at all; one that refuses says no.
            if h.is_offline() {
                continue;
            }
            let _ = tx.send(h.publish(ev));
        }
        PublishAck::new(rx, self.hubs.len())
    }

    fn subscribe(&self, filters: Vec<Filter>) -> Subscription {
        let (tx, rx) = mpsc::channel(SUB_QUEUE);
        let (stx, srx) = watch::channel(SubStatus::Connecting);
        let stx = Arc::new(stx);
        let mut opened = Vec::new();
        let down = Arc::new(AtomicUsize::new(0));
        for h in &self.hubs {
            match h.open(self.connection, filters.clone(), tx.clone(), stx.clone()) {
                Some(id) => opened.push((h.clone(), id)),
                None => {
                    down.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let close: CloseFn = Box::new(move || {
            for (h, id) in opened {
                h.close(id);
            }
        });
        Subscription::new(rx, self.hubs.len(), Some(close)).with_unreachable_counter(down).with_status(srx)
    }

    fn urls(&self) -> Vec<String> {
        self.urls.clone()
    }
}

// ─── Live websocket relays ──────────────────────────────────────────────────

/// Connects to real relays over websockets, on the crate runtime, using the
/// process-wide [`RelayPool`]. The unit value is the stock connector.
#[derive(Clone, Copy, Default)]
pub struct WsConnector;

impl Connector for WsConnector {
    fn connect(&self, urls: &[String]) -> Arc<dyn Relay> {
        Arc::new(WsRelaySet::start_in(RelayPool::global(), urls, false))
    }

    fn connect_main(&self, urls: &[String]) -> Arc<dyn Relay> {
        Arc::new(WsRelaySet::start_in(RelayPool::global(), urls, true))
    }
}

/// Answers a relay's NIP-42 challenge: given the relay URL and the challenge,
/// the signed kind 22242 event to send back (`None`: cannot sign, so the
/// challenge goes unanswered). Authenticating is opt-in: only a connector built
/// with one ([`AuthConnector`], [`WsRelaySet::start_authed`]) ever answers.
pub type AuthSigner = Arc<dyn Fn(&str, &str) -> Option<Event> + Send + Sync>;

/// An [`AuthSigner`] that signs with `keys`.
pub fn auth_signer(keys: Keys) -> AuthSigner {
    Arc::new(move |url, challenge| {
        let url = RelayUrl::parse(url).ok()?;
        EventBuilder::auth(challenge, url).sign_with_keys(&keys).ok()
    })
}

/// A [`WsConnector`] whose relays are answered when they challenge for NIP-42
/// authentication (a relay that wants to know who is asking before it serves
/// a read). The relays are the listed ones only; there is no fallback. Give it one
/// URL per set (as the Keep does): a subscription over several shares one status.
#[derive(Clone)]
pub struct AuthConnector {
    signer: AuthSigner,
}

impl AuthConnector {
    pub fn new(signer: AuthSigner) -> Self {
        AuthConnector { signer }
    }
}

impl Connector for AuthConnector {
    fn connect(&self, urls: &[String]) -> Arc<dyn Relay> {
        Arc::new(WsRelaySet::start_authed(RelayPool::global(), urls, self.signer.clone()))
    }
}

/// A [`WsConnector`] on a pool of its own (tests: short backoff, own defaults).
#[derive(Clone)]
pub struct PoolConnector {
    pool: Arc<RelayPool>,
}

impl PoolConnector {
    pub fn new(pool: Arc<RelayPool>) -> Self {
        PoolConnector { pool }
    }
}

impl Connector for PoolConnector {
    fn connect(&self, urls: &[String]) -> Arc<dyn Relay> {
        Arc::new(WsRelaySet::start_in(self.pool.clone(), urls, false))
    }

    fn connect_main(&self, urls: &[String]) -> Arc<dyn Relay> {
        Arc::new(WsRelaySet::start_in(self.pool.clone(), urls, true))
    }
}

/// A write on its way to one relay.
struct Pending {
    ev: Box<Event>,
    at: Instant,
    ack: Option<mpsc::UnboundedSender<bool>>,
}

enum Cmd {
    Publish(Box<Event>, Option<mpsc::UnboundedSender<bool>>),
    Req { id: String, filters: Vec<Filter>, tx: mpsc::Sender<RelayMsg>, down: Arc<AtomicUsize>, status: Arc<watch::Sender<SubStatus>> },
    Close(String),
    /// [`Relay::reconnect`], asked at this time. A wake asked before the
    /// current connection was made is stale: the dial it wanted is done.
    Wake(Instant),
}

/// Why a session ended when it was asked to ([`Cmd::Wake`]): not a failure.
const WOKE: &str = "reconnecting";

type Worker = mpsc::UnboundedSender<Cmd>;

/// One websocket worker per URL. Dropping the set stops the workers.
pub struct WsRelaySet {
    /// The listed relays, in the player's order, each once.
    workers: Vec<(String, Worker)>,
    urls: Vec<String>,
    pool: Arc<RelayPool>,
    /// May the built-in defaults stand in when every listed relay is failing?
    fallback: bool,
    /// Workers for the defaults, started the first time they are needed.
    reserve: Mutex<Vec<(String, Worker)>>,
    /// Answers NIP-42 challenges, if the set is to.
    auth: Option<AuthSigner>,
}

static NEXT_SUB: AtomicU64 = AtomicU64::new(1);

impl WsRelaySet {
    /// On the process-wide pool, no fallback.
    pub fn start(urls: &[String]) -> Self {
        Self::start_in(RelayPool::global(), urls, false)
    }

    /// Workers for `urls` (deduplicated, order kept) on `pool`. With
    /// `fallback`, the pool's defaults are asked too while every listed relay
    /// is failing.
    pub fn start_in(pool: Arc<RelayPool>, urls: &[String], fallback: bool) -> Self {
        Self::start_with(pool, urls, fallback, None)
    }

    /// On `pool`, no fallback, answering NIP-42 challenges with `auth`.
    pub fn start_authed(pool: Arc<RelayPool>, urls: &[String], auth: AuthSigner) -> Self {
        Self::start_with(pool, urls, false, Some(auth))
    }

    fn start_with(pool: Arc<RelayPool>, urls: &[String], fallback: bool, auth: Option<AuthSigner>) -> Self {
        // rustls needs a process-wide crypto provider for wss://. Installing
        // one fails harmlessly when the app (or another crate) already did.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let urls = pool.order(urls);
        let workers = urls.iter().map(|u| (u.clone(), spawn_worker(u, &pool, &auth))).collect();
        WsRelaySet { workers, urls, pool, fallback, reserve: Mutex::new(Vec::new()), auth }
    }

    /// The default relays to ask as well right now (none unless a fallback is
    /// allowed and every listed relay is failing). Starts their workers on first use.
    fn extras(&self) -> Vec<Worker> {
        if !self.fallback {
            return Vec::new();
        }
        let want = self.pool.fallback_extras(&self.urls);
        self.pool.refresh_fallback(&self.urls);
        if want.is_empty() {
            return Vec::new();
        }
        let mut g = self.reserve.lock().unwrap_or_else(|e| e.into_inner());
        want.iter()
            .map(|u| match g.iter().find(|(k, _)| k == u) {
                Some((_, w)) => w.clone(),
                None => {
                    let w = spawn_worker(u, &self.pool, &self.auth);
                    g.push((u.clone(), w.clone()));
                    w
                }
            })
            .collect()
    }

    /// Where a write goes: the top healthy relays in order; if none is healthy
    /// the whole list (the write waits in each worker's queue); and the
    /// defaults too while every listed relay is failing.
    fn write_targets(&self) -> Vec<Worker> {
        let chosen = self.pool.writers(&self.urls);
        let mut out: Vec<Worker> = if chosen.is_empty() {
            self.workers.iter().map(|(_, w)| w.clone()).collect()
        } else {
            chosen
                .iter()
                .filter_map(|u| self.workers.iter().find(|(k, _)| k == u).map(|(_, w)| w.clone()))
                .collect()
        };
        out.extend(self.extras());
        out
    }

    fn event_targets(&self, ev: &Event) -> Vec<Worker> {
        if ev.kind == Kind::NostrConnect {
            // Ephemeral RPC needs the signer's actual listening relay. A
            // healthy content relay's ACK does not prove signer delivery.
            // Queue the same envelope on every approved URL, including those
            // currently backed off, and never add unapproved fallback URLs.
            self.workers.iter().map(|(_, w)| w.clone()).collect()
        } else {
            self.write_targets()
        }
    }
}

fn spawn_worker(url: &str, pool: &Arc<RelayPool>, auth: &Option<AuthSigner>) -> Worker {
    let (tx, rx) = mpsc::unbounded_channel();
    crate::runtime().spawn(ws_worker(url.to_string(), rx, pool.clone(), auth.clone()));
    tx
}

impl Relay for WsRelaySet {
    fn publish(&self, ev: &Event) {
        for w in self.event_targets(ev) {
            let _ = w.send(Cmd::Publish(Box::new(ev.clone()), None));
        }
    }

    fn publish_acked(&self, ev: &Event) -> PublishAck {
        let targets = self.event_targets(ev);
        let (tx, rx) = mpsc::unbounded_channel();
        for w in &targets {
            let _ = w.send(Cmd::Publish(Box::new(ev.clone()), Some(tx.clone())));
        }
        PublishAck::new(rx, targets.len())
    }

    fn subscribe(&self, filters: Vec<Filter>) -> Subscription {
        let (tx, rx) = mpsc::channel(SUB_QUEUE);
        let id = format!("ds{}", NEXT_SUB.fetch_add(1, Ordering::Relaxed));
        let down = Arc::new(AtomicUsize::new(0));
        let (stx, srx) = watch::channel(SubStatus::Connecting);
        let stx = Arc::new(stx);
        let mut workers: Vec<Worker> = self.workers.iter().map(|(_, w)| w.clone()).collect();
        workers.extend(self.extras());
        for w in &workers {
            // The relay's own queue, and a forwarder into the shared one. Waiting
            // senders are served in turn, so every relay gets its share.
            let (rtx, mut rrx) = mpsc::channel(RELAY_QUEUE);
            let out = tx.clone();
            crate::runtime().spawn(async move {
                while let Some(m) = rrx.recv().await {
                    if out.send(m).await.is_err() {
                        break;
                    }
                }
            });
            let _ = w.send(Cmd::Req { id: id.clone(), filters: filters.clone(), tx: rtx, down: down.clone(), status: stx.clone() });
        }
        let n = workers.len();
        let close: CloseFn = Box::new(move || {
            for w in workers {
                let _ = w.send(Cmd::Close(id.clone()));
            }
        });
        Subscription::new(rx, n, Some(close)).with_unreachable_counter(down).with_status(srx)
    }

    fn urls(&self) -> Vec<String> {
        self.urls.clone()
    }

    fn reconnect(&self) {
        for (_, w) in &self.workers {
            let _ = w.send(Cmd::Wake(Instant::now()));
        }
        for w in self.extras() {
            let _ = w.send(Cmd::Wake(Instant::now()));
        }
    }

    fn fallback_ready(&self) -> bool {
        self.fallback && !self.pool.fallback_extras(&self.urls).is_empty()
    }
}

const DIAL_TIMEOUT: Duration = Duration::from_secs(6);
const SEND_TIMEOUT: Duration = Duration::from_secs(4);
const PUBLISH_TTL: Duration = Duration::from_secs(120);
const MAX_PENDING_PUBLISH: usize = 32;
/// Largest websocket message accepted from a relay (projections are padded
/// to at most 64 KiB, then base64 + JSON).
const MAX_WS_MESSAGE: usize = 512 * 1024;

struct WorkerSub {
    filters: Vec<Filter>,
    tx: mpsc::Sender<RelayMsg>,
    /// This connection has had the relay's EOSE (or CLOSED) for the REQ.
    eosed: bool,
    /// An EOSE has gone to the consumer for this relay, its own or a made-up
    /// one. A consumer counts one per relay, so no second one goes out on a
    /// redial; only a [`Cmd::Wake`] (a fresh listen) starts over.
    told: bool,
    /// The EOSE told was made up, and `down` counts it.
    faked: bool,
    down: Arc<AtomicUsize>,
    status: Arc<watch::Sender<SubStatus>>,
    /// When the REQ went out, for the response-time record.
    asked: Instant,
    /// Events the relay has sent for the REQ on this connection before its EOSE.
    got: usize,
    /// The most an honest relay sends before its EOSE: the sum of the
    /// filters' `limit`s, when every filter has one. Past it the rest of the
    /// stored answer is dropped unchecked. `None` (no bound) otherwise, as for
    /// the standing subscriptions.
    cap: Option<usize>,
}

/// [`WorkerSub::cap`] for `filters`.
fn stored_cap(filters: &[Filter]) -> Option<usize> {
    if filters.is_empty() {
        return None;
    }
    filters.iter().try_fold(0usize, |n, f| f.limit.map(|l| n.saturating_add(l)))
}

impl WorkerSub {
    /// The relay has ended its answer on this connection: with its own EOSE
    /// (`own`), or a CLOSED. The consumer hears one EOSE per relay; a relay
    /// that comes back with its own after a made-up one is no longer counted
    /// as unreachable. Not across a [`Cmd::Wake`]: [`WorkerSub::listen_afresh`]
    /// forgets the made-up one, and it stays counted.
    fn end(&mut self, own: bool) {
        self.eosed = true;
        if !self.told {
            self.told = true;
            let _ = self.tx.try_send(RelayMsg::Eose);
        } else if own && self.faked {
            self.faked = false;
            self.down.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Not going to answer now (a failed dial, a dropped connection).
    fn give_up(&mut self) {
        self.eosed = true;
        if !self.told {
            self.told = true;
            self.faked = true;
            self.down.fetch_add(1, Ordering::Relaxed);
            let _ = self.tx.try_send(RelayMsg::Eose);
        }
    }

    /// A fresh listen was asked for ([`Relay::reconnect`]): its EOSE counts again.
    fn listen_afresh(&mut self) {
        self.told = false;
        self.faked = false;
    }
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn req_frame(id: &str, filters: &[Filter]) -> String {
    let mut arr = vec![json!("REQ"), json!(id)];
    for f in filters {
        arr.push(serde_json::to_value(f).unwrap_or(Value::Null));
    }
    Value::Array(arr).to_string()
}

async fn send_text(ws: &mut Socket, text: String) -> bool {
    matches!(tokio::time::timeout(SEND_TIMEOUT, ws.send(Message::Text(text.into()))).await, Ok(Ok(())))
}

/// What a relay frame means to the worker.
enum Frame {
    Event(String, Box<Event>),
    Eose(String),
    Closed(String, String),
    /// Event id, whether it was accepted, and the relay's words.
    Ok(String, bool, String),
    /// NIP-42: the relay's challenge.
    Auth(String),
    Other,
}

fn parse_frame(text: &str) -> Frame {
    let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(text) else { return Frame::Other };
    let s = |i: usize| arr.get(i).and_then(|x| x.as_str()).map(str::to_string);
    match arr.first().and_then(|x| x.as_str()) {
        Some("EVENT") => match (s(1), arr.get(2)) {
            (Some(id), Some(v)) => match serde_json::from_value::<Event>(v.clone()) {
                Ok(ev) => Frame::Event(id, Box::new(ev)),
                Err(_) => Frame::Other,
            },
            _ => Frame::Other,
        },
        Some("EOSE") => s(1).map_or(Frame::Other, Frame::Eose),
        Some("CLOSED") => s(1).map_or(Frame::Other, |id| Frame::Closed(id, s(2).unwrap_or_default())),
        Some("OK") => match (s(1), arr.get(2).and_then(|x| x.as_bool())) {
            (Some(id), Some(accepted)) => Frame::Ok(id, accepted, s(3).unwrap_or_default()),
            _ => Frame::Other,
        },
        Some("AUTH") => s(1).map_or(Frame::Other, Frame::Auth),
        _ => Frame::Other,
    }
}

/// [`parse_frame`], noting that the relay said something on this connection.
fn heard_frame(heard: &mut bool, text: &str) -> Frame {
    *heard = true;
    parse_frame(text)
}

/// Does a relay's CLOSED text say it wants authentication (NIP-42's prefix)?
fn wants_auth(text: &str) -> bool {
    // Some relays put their own "ERROR: " in front of the prefix.
    text.to_ascii_lowercase().contains("auth-required:")
}

/// Most challenges answered on one connection: a relay that keeps challenging
/// is not answered for ever.
const MAX_AUTH_PER_CONNECTION: u8 = 3;

/// Where NIP-42 stands on one connection.
struct AuthState {
    signer: Option<AuthSigner>,
    /// Challenges answered on this connection.
    answered: u8,
    /// The ids of the AUTH events sent and not yet answered by an OK (at most
    /// [`MAX_AUTH_PER_CONNECTION`]).
    in_flight: Vec<String>,
    /// Requests the relay closed `auth-required` while an answer was on its
    /// way: neither failed nor over until its OK comes, or [`AUTH_WAIT`] passes.
    /// Id and the relay's text.
    held: HashMap<String, String>,
    /// When the oldest held request stops being held.
    deadline: Option<tokio::time::Instant>,
}

impl AuthState {
    fn new(signer: Option<AuthSigner>) -> Self {
        AuthState { signer, answered: 0, in_flight: Vec::new(), held: HashMap::new(), deadline: None }
    }

    /// The relay did not take the answer, or gave none in time: the requests
    /// held for it end closed, with the relay's own words, as any CLOSED does.
    fn release(&mut self, subs: &mut HashMap<String, WorkerSub>) {
        self.deadline = None;
        for (id, text) in std::mem::take(&mut self.held) {
            if let Some(s) = subs.get_mut(&id) {
                s.status.send_replace(SubStatus::Closed(why(&text)));
                if !s.eosed {
                    s.end(false);
                }
            }
        }
    }
}

/// How long a request the relay closed `auth-required` is held for the OK to
/// the answer. Well inside what a reader waits for a page.
const AUTH_WAIT: Duration = Duration::from_secs(4);

/// The longest challenge answered, and it must be printable ASCII: a relay's
/// challenge is signed back verbatim, never cut.
const MAX_CHALLENGE: usize = 256;

fn fit_challenge(c: &str) -> bool {
    !c.is_empty() && c.len() <= MAX_CHALLENGE && c.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// A short, secret-free reason for the log and for the dot's toast. A relay
/// writes some of these words itself, so nothing that could break or reorder
/// a log line is kept.
fn why(e: &dyn std::fmt::Display) -> String {
    e.to_string().chars().filter(|c| !crate::hidden_char(*c)).take(120).collect()
}

/// Hold the worker for `wait` (a backoff), still taking commands. A read that
/// arrives meanwhile is answered at once with a made-up EOSE (counted as
/// unreachable) so a fetch is not held up; its REQ goes out on reconnect.
/// `false` = the command channel closed (stop).
async fn idle(
    why_down: &str,
    wait: Duration,
    rx: &mut mpsc::UnboundedReceiver<Cmd>,
    subs: &mut HashMap<String, WorkerSub>,
    pending: &mut VecDeque<Pending>,
) -> bool {
    let wake = tokio::time::Instant::now() + wait;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(wake) => return true,
            cmd = rx.recv() => match cmd {
                None => return false,
                Some(Cmd::Publish(ev, ack)) => {
                    if pending.len() >= MAX_PENDING_PUBLISH {
                        pending.pop_front();
                    }
                    // This relay is down for now: it gives no answer for the write.
                    drop(ack);
                    pending.push_back(Pending { ev, at: Instant::now(), ack: None });
                }
                Some(Cmd::Req { id, filters, tx, down, status }) => {
                    status.send_replace(SubStatus::Down(why_down.to_string()));
                    let cap = stored_cap(&filters);
                    let mut s = WorkerSub { filters, tx, eosed: false, told: false, faked: false, down, status, asked: Instant::now(), got: 0, cap };
                    s.give_up();
                    subs.insert(id, s);
                }
                Some(Cmd::Close(id)) => {
                    subs.remove(&id);
                }
                // Dial now instead of waiting out the backoff.
                Some(Cmd::Wake(_)) => {
                    subs.values_mut().for_each(WorkerSub::listen_afresh);
                    return true;
                }
            }
        }
    }
}

/// A session that ends sooner than this with a request out and nothing heard
/// from the relay counts toward this worker's own backoff (see `ws_worker`).
const SHORT_SESSION: Duration = Duration::from_secs(30);

async fn ws_worker(url: String, mut rx: mpsc::UnboundedReceiver<Cmd>, pool: Arc<RelayPool>, auth: Option<AuthSigner>) {
    let mut subs: HashMap<String, WorkerSub> = HashMap::new();
    let mut pending: VecDeque<Pending> = VecDeque::new();
    let mut cfg = WebSocketConfig::default();
    cfg.max_message_size = Some(MAX_WS_MESSAGE);
    cfg.max_frame_size = Some(MAX_WS_MESSAGE);
    // A relay that takes the connection and drops it at once, saying nothing
    // to a request that is out, has its pool backoff reset by every
    // handshake. Such sessions in a row are counted here, and the next dial
    // waits the pool's schedule for that many failures. Any frame counts as
    // said, a NOTICE too. A connection with no request out is not counted: an
    // honest relay may close an idle connection soon. Pool health itself is
    // left alone.
    let mut short: u32 = 0;
    let mut hold = Duration::ZERO;
    loop {
        // Backed off? Wait it out (taking commands); the dial below is the re-probe.
        let wait = pool.wait_for(&url).max(std::mem::take(&mut hold));
        if !wait.is_zero() {
            let why_down = pool.last_error(&url).unwrap_or_else(|| "backing off".to_string());
            // A request the relay CLOSED stays closed until the next dial: it
            // refused, whatever happened to the connection after.
            for s in subs.values() {
                if !matches!(*s.status.borrow(), SubStatus::Closed(_)) {
                    s.status.send_replace(SubStatus::Down(why_down.clone()));
                }
            }
            if !idle(&why_down, wait, &mut rx, &mut subs, &mut pending).await {
                return;
            }
        }
        let started = Instant::now();
        let dial = tokio::time::timeout(
            DIAL_TIMEOUT,
            tokio_tungstenite::connect_async_with_config(url.as_str(), Some(cfg), false),
        )
        .await;
        let failure: String = match dial {
            Ok(Ok((mut ws, _))) => {
                let took = started.elapsed();
                log::info!("[relays] connected {url} in {} ms", took.as_millis());
                pool.record_success(&url, Some(took));
                let mut ok = true;
                for (id, s) in subs.iter_mut() {
                    s.eosed = false;
                    s.got = 0;
                    s.status.send_replace(SubStatus::Up);
                    s.asked = Instant::now();
                    ok &= send_text(&mut ws, req_frame(id, &s.filters)).await;
                }
                pending.retain(|p| p.at.elapsed() < PUBLISH_TTL);
                let mut awaiting: HashMap<String, mpsc::UnboundedSender<bool>> = HashMap::new();
                while ok && let Some(p) = pending.pop_front() {
                    ok &= send_text(&mut ws, json!(["EVENT", p.ev]).to_string()).await;
                    if let Some(a) = p.ack {
                        awaiting.insert(p.ev.id.to_hex(), a);
                    }
                }
                let mut auth = AuthState::new(auth.clone());
                let connected = Instant::now();
                let mut heard = false;
                let ended = if ok {
                    run_session(&mut ws, &mut rx, &mut subs, &mut awaiting, &mut auth, &url, &pool, connected, &mut heard).await
                } else {
                    Some("send failed".to_string())
                };
                let _ = ws.close(None).await;
                match ended {
                    None => return, // the set was dropped
                    // Asked to redial: not a failure, so no backoff is started.
                    Some(reason) if reason == WOKE => {
                        for s in subs.values_mut() {
                            if !matches!(*s.status.borrow(), SubStatus::Closed(_)) {
                                s.status.send_replace(SubStatus::Connecting);
                            }
                            s.listen_afresh();
                        }
                        continue;
                    }
                    Some(reason) => {
                        short = if !heard && !subs.is_empty() && connected.elapsed() < SHORT_SESSION { short.saturating_add(1) } else { 0 };
                        if short > 0 {
                            hold = pool.schedule().wait(short);
                        }
                        reason
                    }
                }
            }
            Ok(Err(e)) => why(&e),
            Err(_) => "timed out".to_string(),
        };
        pool.record_failure(&url, &failure);
        // Whatever this relay has not answered yet, it is not going to now.
        for s in subs.values_mut() {
            if !matches!(*s.status.borrow(), SubStatus::Closed(_)) {
                s.status.send_replace(SubStatus::Down(failure.clone()));
            }
            if !s.eosed {
                s.give_up();
            }
        }
        // Nobody waits for an answer from a relay that just went down.
        for p in pending.iter_mut() {
            p.ack = None;
        }
    }
}

/// Run one connected session. `None` = the command channel closed (stop);
/// `Some(reason)` = the connection ended.
#[allow(clippy::too_many_arguments)]
async fn run_session(
    ws: &mut Socket,
    rx: &mut mpsc::UnboundedReceiver<Cmd>,
    subs: &mut HashMap<String, WorkerSub>,
    awaiting: &mut HashMap<String, mpsc::UnboundedSender<bool>>,
    auth: &mut AuthState,
    url: &str,
    pool: &RelayPool,
    since: Instant,
    heard: &mut bool,
) -> Option<String> {
    loop {
        tokio::select! {
            // No OK for the answer in time: what was held for it is closed.
            _ = tokio::time::sleep_until(auth.deadline.unwrap_or_else(tokio::time::Instant::now)), if auth.deadline.is_some() => {
                auth.release(subs);
            }
            cmd = rx.recv() => match cmd {
                None => return None,
                Some(Cmd::Publish(ev, ack)) => {
                    if let Some(a) = ack {
                        awaiting.insert(ev.id.to_hex(), a);
                    }
                    if !send_text(ws, json!(["EVENT", ev]).to_string()).await {
                        return Some("send failed".into());
                    }
                }
                Some(Cmd::Req { id, filters, tx, down, status }) => {
                    let frame = req_frame(&id, &filters);
                    let cap = stored_cap(&filters);
                    status.send_replace(SubStatus::Up);
                    subs.insert(id, WorkerSub { filters, tx, eosed: false, told: false, faked: false, down, status, asked: Instant::now(), got: 0, cap });
                    if !send_text(ws, frame).await {
                        return Some("send failed".into());
                    }
                }
                Some(Cmd::Close(id)) => {
                    if subs.remove(&id).is_some() && !send_text(ws, json!(["CLOSE", id]).to_string()).await {
                        return Some("send failed".into());
                    }
                }
                // One asked for while this connection was still being dialled is
                // stale: this is the fresh connection it asked for.
                Some(Cmd::Wake(at)) if at > since => return Some(WOKE.into()),
                Some(Cmd::Wake(_)) => {}
            },
            msg = ws.next() => match msg {
                Some(Ok(Message::Text(text))) => match heard_frame(heard, &text) {
                    Frame::Event(id, ev) => {
                        let Some(s) = subs.get_mut(&id) else { continue };
                        // Before its EOSE an honest relay sends at most the
                        // filters' limits: the rest is not even verified.
                        if !s.eosed {
                            s.got = s.got.saturating_add(1);
                            if s.cap.is_some_and(|cap| s.got > cap) {
                                continue;
                            }
                        }
                        // The last free slot of the relay's share is kept for its EOSE.
                        if s.tx.capacity() <= 1 || !matches_any(&s.filters, &ev) || !event_ok(&ev) {
                            continue;
                        }
                        if let Err(mpsc::error::TrySendError::Closed(_)) = s.tx.try_send(RelayMsg::Event(ev)) {
                            subs.remove(&id);
                            if !send_text(ws, json!(["CLOSE", id]).to_string()).await {
                                return Some("send failed".into());
                            }
                        }
                    }
                    Frame::Eose(id) => {
                        if let Some(s) = subs.get_mut(&id)
                            && !s.eosed
                        {
                            pool.record_latency(url, s.asked.elapsed());
                            s.end(true);
                        }
                    }
                    Frame::Closed(id, text) => {
                        // Told to authenticate, and the answer is already on its
                        // way: the request is asked again when the relay accepts it.
                        if !auth.in_flight.is_empty() && wants_auth(&text) && subs.contains_key(&id) {
                            auth.deadline.get_or_insert_with(|| tokio::time::Instant::now() + AUTH_WAIT);
                            auth.held.insert(id, text);
                            continue;
                        }
                        if let Some(s) = subs.get_mut(&id) {
                            log::info!("[relays] {url} CLOSED a subscription: {}", why(&text));
                            s.status.send_replace(SubStatus::Closed(why(&text)));
                            if !s.eosed {
                                s.end(false);
                            }
                        }
                    }
                    Frame::Auth(challenge) => {
                        let Some(signer) = auth.signer.clone() else { continue };
                        if auth.answered >= MAX_AUTH_PER_CONNECTION || !fit_challenge(&challenge) {
                            continue;
                        }
                        // The signed event is sent and forgotten: it is not logged.
                        let Some(ev) = signer(url, &challenge) else { continue };
                        auth.answered += 1;
                        auth.in_flight.push(ev.id.to_hex());
                        if !send_text(ws, json!(["AUTH", ev]).to_string()).await {
                            return Some("send failed".into());
                        }
                    }
                    Frame::Ok(id, accepted, said) if auth.in_flight.contains(&id) => {
                        auth.in_flight.retain(|f| *f != id);
                        if accepted {
                            log::info!("[relays] authenticated to {url}");
                            // Ask again what was held for it. A request already
                            // shown as closed stays closed on this connection.
                            auth.deadline = None;
                            for id in std::mem::take(&mut auth.held).into_keys() {
                                let Some(s) = subs.get_mut(&id) else { continue };
                                s.eosed = false;
                                s.got = 0;
                                s.asked = Instant::now();
                                s.status.send_replace(SubStatus::Up);
                                if !send_text(ws, req_frame(&id, &s.filters)).await {
                                    return Some("send failed".into());
                                }
                            }
                        } else {
                            let said: String = said.chars().filter(|c| !c.is_control()).take(80).collect();
                            log::info!("[relays] {url} refused the authentication: {said}");
                            // Another answer may still be on its way.
                            if auth.in_flight.is_empty() {
                                auth.release(subs);
                            }
                        }
                    }
                    Frame::Ok(id, accepted, _) => {
                        if let Some(a) = awaiting.remove(&id) {
                            let _ = a.send(accepted);
                        }
                    }
                    Frame::Other => {}
                },
                Some(Ok(_)) => {}
                Some(Err(e)) => return Some(why(&e)),
                None => return Some("connection closed".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decented_relays::Schedule;

    /// A relay on 127.0.0.1 that answers a REQ with CLOSED and then hangs up
    /// (a rate limiter that drops whoever it refuses).
    fn refuse_and_hang_up(rt: &tokio::runtime::Runtime) -> String {
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        rt.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                    while let Some(Ok(Message::Text(t))) = ws.next().await {
                        let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&t) else { continue };
                        if a.first().and_then(|v| v.as_str()) == Some("REQ") {
                            let id = a[1].as_str().unwrap_or("").to_string();
                            let closed = json!(["CLOSED", id, "rate-limited: slow down"]).to_string();
                            let _ = ws.send(Message::Text(closed.into())).await;
                            let _ = ws.close(None).await;
                            return;
                        }
                    }
                });
            }
        });
        url
    }

    /// A reader that gets to the answer late: by the time the subscription is
    /// handed over, the connection has dropped and the backoff has begun.
    struct Late {
        set: WsRelaySet,
        pool: Arc<RelayPool>,
    }

    impl Relay for Late {
        fn publish(&self, _: &Event) {}
        fn subscribe(&self, filters: Vec<Filter>) -> Subscription {
            let sub = self.set.subscribe(filters);
            let url = self.set.urls()[0].clone();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !self.pool.failing(&url) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(300));
            sub
        }
        fn urls(&self) -> Vec<String> {
            self.set.urls()
        }
    }

    /// A relay that refuses the lookup with CLOSED and then hangs up has still
    /// refused it: its EOSE, read after the drop, does not count as "holds
    /// nothing".
    #[test]
    fn a_refusal_then_a_hang_up_does_not_count_as_holding_nothing() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let url = refuse_and_hang_up(&rt);
        // A long backoff: no redial shows the request as up again meanwhile.
        let pool = Arc::new(RelayPool::with(vec![], Schedule::new(vec![Duration::from_secs(30)], Duration::from_secs(30))));
        let late = Late { set: WsRelaySet::start_in(pool.clone(), std::slice::from_ref(&url), false), pool };
        let filters = vec![Filter::new().kind(Kind::TextNote)];
        let report = rt.block_on(fetch_unless_refused(&late, filters, Duration::from_secs(5)));
        assert!(late.pool.failing(&url), "the hang-up was recorded");
        assert_eq!(report.answered, 0, "{report:?}");
    }
}
