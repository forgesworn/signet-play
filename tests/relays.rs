//! Relay order, parallel reads and writes, honest "reached / unreachable",
//! reconnect and the defaults fallback, against loopback websocket relays that
//! can be killed, revived and made silent (no internet).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use decented_relays::{Dot, RelayPool, Schedule};
use decented_signet::relay::{
    Connector, FakeNetwork, PoolConnector, Relay, RelayMsg, WsRelaySet, fetch, fetch_first, fetch_report,
};
use futures_util::{SinkExt, StreamExt};
use nostr::{Event, EventBuilder, Filter, Keys, Kind};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

const STORE: &str = "wss://store.test";

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// 60 ms, 120 ms, then 200 ms between re-probes; its own defaults.
fn fast_pool(defaults: Vec<String>) -> Arc<RelayPool> {
    Arc::new(RelayPool::with(defaults, Schedule::new(vec![ms(60), ms(120)], ms(200))))
}

fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(ms(10));
    }
}

fn note(content: &str, keys: &Keys) -> Event {
    EventBuilder::new(Kind::TextNote, content).sign_with_keys(keys).unwrap()
}

/// A loopback relay backed by an in-memory store.
#[derive(Clone)]
struct TestRelay {
    url: String,
    net: FakeNetwork,
    down: Arc<AtomicBool>,
    kill: watch::Sender<u64>,
    /// Never answers anything (a relay that accepts the socket and hangs).
    silent: bool,
    received: Arc<Mutex<Vec<Event>>>,
    reqs: Arc<Mutex<usize>>,
    /// How long the websocket handshake takes (a slow mobile dial); while the
    /// relay is down, how long a dial to it takes to fail.
    handshake: Arc<Mutex<Duration>>,
    /// Takes the websocket and drops it at once (a relay at its connection limit).
    hang_up: Arc<AtomicBool>,
    /// Websocket handshakes completed.
    accepted: Arc<Mutex<usize>>,
    /// Sent ahead of the stored answer to every REQ (a relay flooding a reader).
    flood: Arc<Mutex<Vec<Event>>>,
}

impl TestRelay {
    fn start(rt: &tokio::runtime::Runtime, silent: bool) -> TestRelay {
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (kill, _) = watch::channel(0u64);
        let t = TestRelay {
            url,
            net: FakeNetwork::new(),
            down: Arc::new(AtomicBool::new(false)),
            kill,
            silent,
            received: Arc::new(Mutex::new(Vec::new())),
            reqs: Arc::new(Mutex::new(0)),
            handshake: Arc::new(Mutex::new(Duration::ZERO)),
            hang_up: Arc::new(AtomicBool::new(false)),
            accepted: Arc::new(Mutex::new(0)),
            flood: Arc::new(Mutex::new(Vec::new())),
        };
        let me = t.clone();
        rt.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                if me.down.load(Ordering::Relaxed) {
                    // Refused at once, or once the handshake time has passed
                    // (a dead relay whose dial takes that long to fail).
                    let delay = *me.handshake.lock().unwrap();
                    if !delay.is_zero() {
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            drop(tcp);
                        });
                    }
                    continue;
                }
                let me = me.clone();
                tokio::spawn(async move { me.serve(tcp).await });
            }
        });
        t
    }

    async fn serve(&self, tcp: tokio::net::TcpStream) {
        let delay = *self.handshake.lock().unwrap();
        tokio::time::sleep(delay).await;
        let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else { return };
        *self.accepted.lock().unwrap() += 1;
        if self.hang_up.load(Ordering::Relaxed) {
            return;
        }
        let (mut sink, mut stream) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
        let writer = tokio::spawn(async move {
            while let Some(t) = out_rx.recv().await {
                if sink.send(Message::Text(t.into())).await.is_err() {
                    break;
                }
            }
        });
        let relay = self.net.connect(&[STORE.to_string()]);
        let mut subs: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut kill = self.kill.subscribe();
        loop {
            tokio::select! {
                _ = kill.changed() => break,
                msg = stream.next() => {
                    let Some(Ok(Message::Text(text))) = msg else { break };
                    if self.silent {
                        continue;
                    }
                    let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&text) else { continue };
                    match a.first().and_then(|v| v.as_str()) {
                        Some("EVENT") => {
                            let Ok(ev) = serde_json::from_value::<Event>(a[1].clone()) else { continue };
                            let ok = self.net.hub(STORE).publish(&ev);
                            if ok {
                                self.received.lock().unwrap().push(ev.clone());
                            }
                            let _ = out_tx.send(json!(["OK", ev.id.to_hex(), ok, ""]).to_string());
                        }
                        Some("REQ") => {
                            *self.reqs.lock().unwrap() += 1;
                            let id = a[1].as_str().unwrap_or("").to_string();
                            for ev in self.flood.lock().unwrap().iter() {
                                let _ = out_tx.send(json!(["EVENT", id, ev]).to_string());
                            }
                            let filters: Vec<Filter> =
                                a[2..].iter().filter_map(|f| serde_json::from_value(f.clone()).ok()).collect();
                            let mut sub = relay.subscribe(filters);
                            let tx = out_tx.clone();
                            subs.push(tokio::spawn(async move {
                                while let Some(m) = sub.recv().await {
                                    let frame = match m {
                                        RelayMsg::Event(ev) => json!(["EVENT", id, ev]),
                                        RelayMsg::Eose => json!(["EOSE", id]),
                                    };
                                    if tx.send(frame.to_string()).is_err() {
                                        break;
                                    }
                                }
                            }));
                        }
                        _ => {}
                    }
                }
            }
        }
        for h in subs {
            h.abort();
        }
        writer.abort();
    }

    fn put(&self, ev: &Event) {
        assert!(self.net.hub(STORE).publish(ev));
    }

    fn kill(&self) {
        self.down.store(true, Ordering::Relaxed);
        self.kill.send_modify(|n| *n += 1);
    }

    fn revive(&self) {
        self.down.store(false, Ordering::Relaxed);
    }

    fn received(&self) -> Vec<Event> {
        self.received.lock().unwrap().clone()
    }

    fn reqs(&self) -> usize {
        *self.reqs.lock().unwrap()
    }
}

fn set(pool: &Arc<RelayPool>, urls: &[String], fallback: bool) -> WsRelaySet {
    WsRelaySet::start_in(pool.clone(), urls, fallback)
}

fn text_notes() -> Filter {
    Filter::new().kind(Kind::TextNote)
}

// ── Reads ──────────────────────────────────────────────────────────────────

#[test]
fn a_read_asks_every_relay_at_once_and_merges_what_they_hold() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (a, b, c) = (TestRelay::start(&rt, false), TestRelay::start(&rt, false), TestRelay::start(&rt, false));
    let k = Keys::generate();
    let (shared, only_b, only_c) = (note("shared", &k), note("only b", &k), note("only c", &k));
    a.put(&shared);
    b.put(&shared);
    b.put(&only_b);
    c.put(&only_c);
    let s = set(&fast_pool(vec![]), &[a.url.clone(), b.url.clone(), c.url.clone()], false);
    let report = rt.block_on(fetch_report(&s, vec![text_notes()], Duration::from_secs(5)));
    let mut ids: Vec<_> = report.events.iter().map(|e| e.id).collect();
    ids.sort();
    let mut want = vec![shared.id, only_b.id, only_c.id];
    want.sort();
    assert_eq!(ids, want, "merged, with the shared event once");
    assert_eq!((report.answered, report.total), (3, 3));
}

#[test]
fn a_feature_that_needs_one_answer_does_not_wait_for_a_silent_relay() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (silent, quick) = (TestRelay::start(&rt, true), TestRelay::start(&rt, false));
    let k = Keys::generate();
    let ev = note("the answer", &k);
    quick.put(&ev);
    // The silent relay is first in the player's order, and still does not hold anything up.
    let s = set(&fast_pool(vec![]), &[silent.url.clone(), quick.url.clone()], false);
    let t0 = Instant::now();
    let report = rt.block_on(fetch_first(&s, vec![text_notes()], Duration::from_secs(10), |_| true));
    assert_eq!(report.events.len(), 1);
    assert!(t0.elapsed() < Duration::from_secs(3), "returned on the first answer: {:?}", t0.elapsed());
    // Reading everything has to wait out the silent relay until the timeout.
    let t1 = Instant::now();
    let full = rt.block_on(fetch(&s, vec![text_notes()], ms(1200)));
    assert_eq!(full.len(), 1);
    assert!(t1.elapsed() >= ms(1100), "{:?}", t1.elapsed());
}

#[test]
fn reached_and_empty_is_told_apart_from_unreachable() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Fake network: relays that answer with nothing...
    let net = FakeNetwork::new();
    let urls: Vec<String> = (0..3).map(|i| format!("wss://r{i}.test")).collect();
    let s = net.connect(&urls);
    let report = rt.block_on(fetch_report(&*s, vec![text_notes()], ms(500)));
    assert!(report.events.is_empty());
    assert!(report.reached(), "they answered: nothing is published");
    assert_eq!((report.answered, report.total), (3, 3));
    // ...two of them down: still reached.
    net.hub(&urls[0]).set_offline(true);
    net.hub(&urls[1]).set_offline(true);
    let report = rt.block_on(fetch_report(&*s, vec![text_notes()], ms(500)));
    assert_eq!((report.answered, report.total), (1, 3));
    assert!(report.reached());
    // ...all down: unreachable.
    net.hub(&urls[2]).set_offline(true);
    let report = rt.block_on(fetch_report(&*s, vec![text_notes()], ms(500)));
    assert!(!report.reached());
    assert_eq!((report.answered, report.total), (0, 3));
}

#[test]
fn over_websockets_a_dead_relay_is_unreachable_and_an_empty_one_is_reached() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let empty = TestRelay::start(&rt, false);
    let dead = TestRelay::start(&rt, false);
    dead.kill();
    let pool = fast_pool(vec![]);
    let reached = rt.block_on(fetch_report(&set(&pool, std::slice::from_ref(&empty.url), false), vec![text_notes()], Duration::from_secs(5)));
    assert!(reached.reached() && reached.events.is_empty());
    let t0 = Instant::now();
    let none = rt.block_on(fetch_report(&set(&pool, std::slice::from_ref(&dead.url), false), vec![text_notes()], Duration::from_secs(5)));
    assert!(!none.reached(), "{none:?}");
    assert!(t0.elapsed() < Duration::from_secs(4));
    assert!(pool.failing(&dead.url) && !pool.failing(&empty.url));
    assert!(pool.view(&dead.url).last_error.is_some(), "the reason is kept for the toast");
}

// ── Writes ─────────────────────────────────────────────────────────────────

#[test]
fn a_write_succeeds_when_one_of_three_relays_is_up() {
    let net = FakeNetwork::new();
    let urls: Vec<String> = (0..3).map(|i| format!("wss://r{i}.test")).collect();
    let s = net.connect(&urls);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let k = Keys::generate();
    net.hub(&urls[0]).set_offline(true);
    net.hub(&urls[1]).set_offline(true);
    let r = rt.block_on(s.publish_acked(&note("hi", &k)).wait(ms(500)));
    assert_eq!((r.targets, r.ok), (3, 1));
    assert!(r.succeeded());
    // A relay that says no is "refused", not a success.
    net.hub(&urls[2]).set_refusing(true);
    let r = rt.block_on(s.publish_acked(&note("hi again", &k)).wait(ms(500)));
    assert_eq!((r.ok, r.refused), (0, 1));
    assert!(!r.succeeded());
}

#[test]
fn over_websockets_a_write_needs_just_one_ok() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (a, b, c) = (TestRelay::start(&rt, false), TestRelay::start(&rt, false), TestRelay::start(&rt, false));
    // Two dead relays whose dials take a second to fail, so the write is
    // aimed at all three before either is known to be down. A relay that has
    // already failed is backed off and left out of a write: had a dial to a
    // dead relay failed first, the targets would depend on the scheduler.
    for dead in [&a, &b] {
        *dead.handshake.lock().unwrap() = Duration::from_secs(1);
        dead.kill();
    }
    let urls = vec![a.url.clone(), b.url.clone(), c.url.clone()];
    let ev = note("offer", &Keys::generate());
    let s = set(&fast_pool(vec![]), &urls, false);
    let r = rt.block_on(s.publish_acked(&ev).wait(Duration::from_secs(5)));
    assert_eq!(r.targets, 3, "{r:?}");
    assert_eq!(r.ok, 1, "{r:?}");
    assert!(r.succeeded());
    assert_eq!(c.received().len(), 1);
}

#[test]
fn writes_go_to_the_top_healthy_relays_in_the_players_order() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relays: Vec<TestRelay> = (0..7).map(|_| TestRelay::start(&rt, false)).collect();
    let urls: Vec<String> = relays.iter().map(|r| r.url.clone()).collect();
    let pool = fast_pool(vec![]);
    // The player's top relay has just failed; it is backed off.
    pool.record_failure(&urls[0], "refused");
    let s = set(&pool, &urls, false);
    let r = rt.block_on(s.publish_acked(&note("x", &Keys::generate())).wait(Duration::from_secs(5)));
    assert_eq!(r.targets, 5, "the top five healthy relays");
    assert_eq!(r.ok, 5);
    for (i, relay) in relays.iter().enumerate() {
        assert_eq!(relay.received().len(), usize::from((1..=5).contains(&i)), "relay {i}");
    }
}

// ── Health, reconnect, fallback ────────────────────────────────────────────

#[test]
fn signer_requests_reach_every_approved_relay_despite_content_write_ranking() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relays: Vec<TestRelay> = (0..7).map(|_| TestRelay::start(&rt, false)).collect();
    let urls: Vec<String> = relays.iter().map(|r| r.url.clone()).collect();
    let fallback = TestRelay::start(&rt, false);
    let pool = fast_pool(vec![fallback.url.clone()]);
    pool.record_failure(&urls[0], "temporarily unavailable");
    let s = set(&pool, &urls, true);
    let keys = Keys::generate();
    let request = |content| EventBuilder::new(Kind::NostrConnect, content).sign_with_keys(&keys).unwrap();
    let unacked = request("first encrypted request");
    s.publish(&unacked);
    let acked = request("second encrypted request");
    let report = rt.block_on(s.publish_acked(&acked).wait(Duration::from_secs(5)));
    assert_eq!(report.targets, urls.len(), "RPC ignores the five-writer cap and health subset");
    assert!(report.succeeded());
    // An early ACK must not cancel delivery to the remaining approved relays,
    // including the backed-off relay when its connection becomes available.
    eventually("both envelopes on every approved relay", || {
        relays.iter().all(|r| {
            let events = r.received();
            events.iter().any(|e| e.id == unacked.id)
                && events.iter().any(|e| e.id == acked.id)
        }).then_some(())
    });
    assert!(fallback.received().is_empty(), "RPC never adds a fallback transport");
    for url in &urls {
        pool.record_failure(url, "all approved transports are backed off");
    }
    assert!(s.fallback_ready(), "content fallback is available");
    let report = rt.block_on(s.publish_acked(&request("third encrypted request")).wait(ms(1)));
    assert_eq!(report.targets, urls.len(), "even active content fallback is excluded from RPC");
}

#[test]
fn a_dropped_relay_is_backed_off_then_recovers_and_a_standing_subscription_is_re_sent() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let a = TestRelay::start(&rt, false);
    let pool = fast_pool(vec![]);
    let s = set(&pool, std::slice::from_ref(&a.url), false);
    let mut sub = s.subscribe(vec![text_notes()]);
    assert!(matches!(eventually("the first EOSE", || sub.try_recv()), RelayMsg::Eose));
    assert_eq!(a.reqs(), 1);
    assert_eq!(pool.dot(&a.url), Dot::Green);
    a.kill();
    eventually("the drop to be recorded", || pool.failing(&a.url).then_some(()));
    assert_eq!(pool.dot(&a.url), Dot::Red);
    std::thread::sleep(ms(300)); // re-probes fail quietly while it is down
    assert!(pool.view(&a.url).failures >= 2, "{:?}", pool.view(&a.url));
    a.revive();
    eventually("the relay to recover and get the REQ again", || (!pool.failing(&a.url) && a.reqs() == 2).then_some(()));
    assert_eq!(pool.dot(&a.url), Dot::Amber, "flaky until the failure leaves the window");
    // The old subscription still delivers: published after the reconnect.
    let ev = note("after the drop", &Keys::generate());
    a.put(&ev);
    let got = eventually("the live event", || match sub.try_recv() {
        Some(RelayMsg::Event(e)) => Some(e),
        _ => None,
    });
    assert_eq!(got.id, ev.id);
}

/// Back from the background: the player's phone cut the network, the relay
/// is backed off for a long time, and the standing subscription must not wait
/// that out once the app asks for a redial.
#[test]
fn a_reconnect_ends_the_backoff_and_redials_at_once() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let a = TestRelay::start(&rt, false);
    let pool = Arc::new(RelayPool::with(vec![], Schedule::new(vec![Duration::from_secs(120)], Duration::from_secs(120))));
    let s = set(&pool, std::slice::from_ref(&a.url), false);
    let mut sub = s.subscribe(vec![text_notes()]);
    assert!(matches!(eventually("the first EOSE", || sub.try_recv()), RelayMsg::Eose));
    a.kill();
    eventually("the drop to be recorded", || pool.failing(&a.url).then_some(()));
    a.revive();
    std::thread::sleep(ms(300));
    assert_eq!(a.reqs(), 1, "still backed off for two minutes");
    let at = Instant::now();
    s.reconnect();
    eventually("the REQ again", || (a.reqs() == 2).then_some(()));
    assert!(at.elapsed() < Duration::from_secs(5));
    let ev = note("after the wake", &Keys::generate());
    a.put(&ev);
    let got = eventually("the live event", || match sub.try_recv() {
        Some(RelayMsg::Event(e)) => Some(e),
        _ => None,
    });
    assert_eq!(got.id, ev.id);
}

/// A connection that looks up is dropped and dialled afresh, without a
/// failure being recorded against the relay.
#[test]
fn a_reconnect_replaces_a_live_connection_without_blaming_the_relay() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let a = TestRelay::start(&rt, false);
    let pool = fast_pool(vec![]);
    let s = set(&pool, std::slice::from_ref(&a.url), false);
    let mut sub = s.subscribe(vec![text_notes()]);
    assert!(matches!(eventually("the first EOSE", || sub.try_recv()), RelayMsg::Eose));
    assert_eq!(a.reqs(), 1);
    s.reconnect();
    eventually("the REQ on the new connection", || (a.reqs() == 2).then_some(()));
    assert_eq!(pool.view(&a.url).failures, 0, "{:?}", pool.view(&a.url));
    assert_eq!(pool.dot(&a.url), Dot::Green);
}

/// Back from the background on a slow link: the dial takes 5 s, and a
/// reconnect asked for 2 s in (while it is still dialling) must not kill the
/// connection the moment it opens.
#[test]
fn a_reconnect_asked_during_a_slow_dial_does_not_kill_the_connection() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let a = TestRelay::start(&rt, false);
    *a.handshake.lock().unwrap() = Duration::from_secs(5);
    let pool = fast_pool(vec![]);
    let s = set(&pool, std::slice::from_ref(&a.url), false);
    let mut sub = s.subscribe(vec![text_notes()]);
    std::thread::sleep(Duration::from_secs(2));
    s.reconnect();
    std::thread::sleep(Duration::from_secs(1));
    s.reconnect();
    assert!(matches!(eventually("the EOSE after the slow dial", || sub.try_recv()), RelayMsg::Eose));
    std::thread::sleep(ms(500));
    assert_eq!(a.reqs(), 1, "the new connection was not dropped for a stale reconnect");
    let ev = note("after the slow dial", &Keys::generate());
    a.put(&ev);
    let got = eventually("the live event", || match sub.try_recv() {
        Some(RelayMsg::Event(e)) => Some(e),
        _ => None,
    });
    assert_eq!(got.id, ev.id);
    assert_eq!(a.reqs(), 1);
}

#[test]
fn a_backed_off_relay_is_skipped_by_a_read_until_its_time() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let a = TestRelay::start(&rt, false);
    let k = Keys::generate();
    a.put(&note("held", &k));
    let pool = Arc::new(RelayPool::with(vec![], Schedule::new(vec![Duration::from_secs(30)], Duration::from_secs(30))));
    pool.record_failure(&a.url, "refused");
    let s = set(&pool, std::slice::from_ref(&a.url), false);
    let report = rt.block_on(fetch_report(&s, vec![text_notes()], Duration::from_secs(5)));
    assert!(report.events.is_empty() && !report.reached(), "not asked while backed off: {report:?}");
    assert_eq!(a.reqs(), 0);
}

#[test]
fn when_every_listed_relay_is_down_the_defaults_are_tried_and_the_notice_is_set() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (l1, l2, d) = (TestRelay::start(&rt, false), TestRelay::start(&rt, false), TestRelay::start(&rt, false));
    l1.kill();
    l2.kill();
    let k = Keys::generate();
    let ev = note("from a default", &k);
    d.put(&ev);
    let pool = fast_pool(vec![d.url.clone()]);
    let connector = PoolConnector::new(pool.clone());
    let main = connector.connect_main(&[l1.url.clone(), l2.url.clone()]);
    let report = rt.block_on(fetch_report(&*main, vec![text_notes()], Duration::from_secs(5)));
    assert_eq!(report.events.len(), 1, "{report:?}");
    assert!(report.reached());
    assert_eq!(pool.notice(), Some("Your relays are unreachable; using defaults"));
    // Without the opt-in (a pairing relay, a signer's relay) the defaults are never asked.
    let (p1, p2) = (TestRelay::start(&rt, false), TestRelay::start(&rt, false));
    p1.kill();
    p2.kill();
    let plain = connector.connect(&[p1.url.clone(), p2.url.clone()]);
    let none = rt.block_on(fetch_report(&*plain, vec![text_notes()], Duration::from_secs(3)));
    assert!(!none.reached());
    assert!(none.events.is_empty());
}

/// A read keeps no more from a relay than an honest relay could send for its
/// filters: what a relay streams before its EOSE past the `limit` is dropped.
#[test]
fn a_read_stops_collecting_past_what_the_filters_allow() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let k = Keys::generate();
    let pool = fast_pool(vec![]);
    let flood = TestRelay::start(&rt, false);
    *flood.flood.lock().unwrap() = (0..300).map(|i| note(&format!("junk {i}"), &k)).collect();
    let s = set(&pool, std::slice::from_ref(&flood.url), false);
    let report = rt.block_on(fetch_report(&s, vec![text_notes().limit(10)], Duration::from_secs(5)));
    assert_eq!(report.events.len(), 10);
    assert!(report.reached());
    // Two filters, each with its own limit: an honest answer to both is kept whole.
    let honest = TestRelay::start(&rt, false);
    *honest.flood.lock().unwrap() = (0..15).map(|i| note(&format!("fine {i}"), &k)).collect();
    let s = set(&pool, std::slice::from_ref(&honest.url), false);
    let report = rt.block_on(fetch_report(
        &s,
        vec![text_notes().limit(10), text_notes().limit(5)],
        Duration::from_secs(5),
    ));
    assert_eq!(report.events.len(), 15);
}

/// One relay flooding a read past its limit does not end the read for the
/// others: a slower relay's answer is still waited for and kept.
#[test]
fn a_flooding_relay_does_not_end_a_read_before_a_slower_relay_answers() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (flood, slow) = (TestRelay::start(&rt, false), TestRelay::start(&rt, false));
    let k = Keys::generate();
    *flood.flood.lock().unwrap() = (0..300).map(|i| note(&format!("old version {i}"), &k)).collect();
    *slow.handshake.lock().unwrap() = ms(800);
    let ev = note("the newest release", &Keys::generate());
    slow.put(&ev);
    let s = set(&fast_pool(vec![]), &[flood.url.clone(), slow.url.clone()], false);
    let report = rt.block_on(fetch_report(&s, vec![text_notes().limit(10)], Duration::from_secs(5)));
    assert!(report.events.iter().any(|e| e.id == ev.id), "the slow relay's event is missing: {} events", report.events.len());
    assert_eq!(report.events.len(), 11, "ten from the flood, one from the slow relay");
    assert_eq!(report.answered, 2);
}

/// A relay back from a backoff inside a read's window answers that read once,
/// not twice: the read still waits for the slow relay that holds the event.
#[test]
fn a_relay_back_from_a_backoff_does_not_answer_twice_for_one_read() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (back, slow) = (TestRelay::start(&rt, false), TestRelay::start(&rt, false));
    *slow.handshake.lock().unwrap() = ms(1500);
    let ev = note("the newest release", &Keys::generate());
    slow.put(&ev);
    let pool = Arc::new(RelayPool::with(vec![], Schedule::new(vec![ms(300)], ms(300))));
    pool.record_failure(&back.url, "refused");
    let s = set(&pool, &[back.url.clone(), slow.url.clone()], false);
    let report = rt.block_on(fetch_report(&s, vec![text_notes()], Duration::from_secs(5)));
    assert_eq!(report.events.len(), 1, "{report:?}");
    assert_eq!(report.answered, 2, "the relay that came back answered: {report:?}");
}

/// A relay that takes each connection and drops it at once, saying nothing
/// (one at its connection limit), is redialled on the growing backoff, not at
/// the first step for ever.
#[test]
fn a_relay_that_accepts_and_drops_is_redialled_ever_more_slowly() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let a = TestRelay::start(&rt, false);
    a.hang_up.store(true, Ordering::Relaxed);
    let pool = Arc::new(RelayPool::with(vec![], Schedule::new(vec![ms(50), ms(400)], Duration::from_secs(5))));
    let s = set(&pool, std::slice::from_ref(&a.url), false);
    let _sub = s.subscribe(vec![text_notes()]);
    std::thread::sleep(ms(1500));
    let dials = *a.accepted.lock().unwrap();
    assert!((2..=4).contains(&dials), "{dials} dials in 1.5 s");
    // A reconnect still dials at once.
    s.reconnect();
    eventually("the dial asked for", || (*a.accepted.lock().unwrap() > dials).then_some(()));
}

/// A relay that closes a connection with no request on it (an honest relay's
/// short idle timeout) is not held off ever longer: it is redialled at the
/// pool's pace, and a read asked for later goes out at once.
#[test]
fn a_relay_that_closes_an_idle_connection_is_not_held_off() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let a = TestRelay::start(&rt, false);
    a.hang_up.store(true, Ordering::Relaxed);
    let pool = Arc::new(RelayPool::with(vec![], Schedule::new(vec![ms(50), ms(400)], Duration::from_secs(5))));
    // No subscription and no write: the connection is idle.
    let s = set(&pool, std::slice::from_ref(&a.url), false);
    std::thread::sleep(ms(1500));
    let dials = *a.accepted.lock().unwrap();
    assert!(dials >= 8, "{dials} dials in 1.5 s");
    // The relay keeps a connection with a request on it.
    a.hang_up.store(false, Ordering::Relaxed);
    let at = Instant::now();
    let _sub = s.subscribe(vec![text_notes()]);
    eventually("the REQ", || (a.reqs() == 1).then_some(()));
    assert!(at.elapsed() < Duration::from_secs(2), "the read was held: {:?}", at.elapsed());
}

/// One relay flooding a subscription fills only its own share of the queue:
/// another relay's event and EOSE still reach a slow reader.
#[test]
fn a_flooding_relay_does_not_crowd_out_another_relays_answer() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (flood, honest) = (TestRelay::start(&rt, false), TestRelay::start(&rt, false));
    let k = Keys::generate();
    *flood.flood.lock().unwrap() = (0..1500).map(|i| note(&format!("junk {i}"), &k)).collect();
    *honest.handshake.lock().unwrap() = ms(500);
    let ev = note("the invite", &Keys::generate());
    honest.put(&ev);
    let s = set(&fast_pool(vec![]), &[flood.url.clone(), honest.url.clone()], false);
    let mut sub = s.subscribe(vec![text_notes()]);
    std::thread::sleep(Duration::from_secs(2)); // a slow reader
    let (mut got, mut eoses) = (false, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !(got && eoses == 2) {
        match sub.try_recv() {
            Some(RelayMsg::Event(e)) => got |= e.id == ev.id,
            Some(RelayMsg::Eose) => eoses += 1,
            None => std::thread::sleep(ms(10)),
        }
    }
    assert!(got, "the honest relay's event was crowded out");
    assert_eq!(eoses, 2, "an EOSE was dropped");
}
