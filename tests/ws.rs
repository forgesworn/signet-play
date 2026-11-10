//! The live websocket relay client, against a loopback websocket server that
//! fronts the in-memory relay (no internet).

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use decented_signet::relay::{Connector, FakeNetwork, RelayMsg, SubStatus, WsConnector, fetch};
use decented_signet::signin::RelayFailure;
use decented_signet::{SignInEvent, Signet};
use futures_util::{SinkExt, StreamExt};
use nostr::{EventBuilder, Filter, Keys, Kind};
use serde_json::{Value, json};
use support::*;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

const T: Duration = Duration::from_secs(10);

/// Serve NIP-01 on 127.0.0.1, backed by `net`'s hub for [`RELAY`].
fn serve(net: FakeNetwork, rt: &tokio::runtime::Runtime) -> String {
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let net = net.clone();
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                let (mut sink, mut stream) = ws.split();
                let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
                tokio::spawn(async move {
                    while let Some(t) = out_rx.recv().await {
                        if sink.send(Message::Text(t.into())).await.is_err() {
                            break;
                        }
                    }
                });
                let relay = net.connect(&[RELAY.to_string()]);
                let mut subs: Vec<(String, tokio::task::JoinHandle<()>)> = Vec::new();
                while let Some(Ok(msg)) = stream.next().await {
                    let Message::Text(text) = msg else { continue };
                    let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&text) else { continue };
                    match a.first().and_then(|v| v.as_str()) {
                        Some("EVENT") => {
                            let Ok(ev) = serde_json::from_value::<nostr::Event>(a[1].clone()) else { continue };
                            let ok = net.hub(RELAY).publish(&ev);
                            let _ = out_tx.send(json!(["OK", ev.id.to_hex(), ok, ""]).to_string());
                        }
                        Some("REQ") => {
                            let id = a[1].as_str().unwrap_or("").to_string();
                            let filters: Vec<Filter> =
                                a[2..].iter().filter_map(|f| serde_json::from_value(f.clone()).ok()).collect();
                            let mut sub = relay.subscribe(filters);
                            let tx = out_tx.clone();
                            let sid = id.clone();
                            let h = tokio::spawn(async move {
                                while let Some(m) = sub.recv().await {
                                    let frame = match m {
                                        RelayMsg::Event(ev) => json!(["EVENT", sid, ev]),
                                        RelayMsg::Eose => json!(["EOSE", sid]),
                                    };
                                    if tx.send(frame.to_string()).is_err() {
                                        break;
                                    }
                                }
                            });
                            subs.push((id, h));
                        }
                        Some("CLOSE") => {
                            let id = a[1].as_str().unwrap_or("");
                            subs.retain(|(s, h)| {
                                if s == id {
                                    h.abort();
                                }
                                s != id
                            });
                        }
                        _ => {}
                    }
                }
                for (_, h) in subs {
                    h.abort();
                }
            });
        }
    });
    url
}

#[test]
fn publish_fetch_and_live_subscription_over_websockets() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let net = FakeNetwork::new();
    let url = serve(net.clone(), &rt);
    let a = WsConnector.connect(std::slice::from_ref(&url));
    let b = WsConnector.connect(std::slice::from_ref(&url));
    let keys = Keys::generate();
    let stored = EventBuilder::new(Kind::Metadata, r#"{"name":"x"}"#).sign_with_keys(&keys).unwrap();
    a.publish(&stored);
    let f = Filter::new().kind(Kind::Metadata).author(keys.public_key());
    let got = wait_for(T, "stored event", || {
        let got = rt.block_on(fetch(&*b, vec![f.clone()], Duration::from_secs(2)));
        (!got.is_empty()).then_some(got)
    });
    assert_eq!(got[0].id, stored.id);

    let mut sub = b.subscribe(vec![Filter::new().kind(Kind::TextNote).author(keys.public_key())]);
    let first = wait_for(T, "eose", || sub.try_recv());
    assert!(matches!(first, RelayMsg::Eose));
    let live = EventBuilder::text_note("hello").sign_with_keys(&keys).unwrap();
    a.publish(&live);
    let got = wait_for(T, "live event", || sub.try_recv());
    let RelayMsg::Event(ev) = got else { panic!() };
    assert_eq!(ev.id, live.id);
}

#[test]
fn an_unreachable_relay_answers_eose_quickly() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dead = WsConnector.connect(&["ws://127.0.0.1:9".to_string()]);
    let t0 = Instant::now();
    let got = rt.block_on(fetch(&*dead, vec![Filter::new().kind(Kind::Metadata)], Duration::from_secs(20)));
    assert!(got.is_empty());
    assert!(t0.elapsed() < Duration::from_secs(8), "{:?}", t0.elapsed());
}

#[test]
fn full_sign_in_over_websockets() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let net = FakeNetwork::new();
    let url = serve(net.clone(), &rt);
    let persona = Keys::generate();
    let signer = FakeMySignet::new(&net, persona.clone());
    let dir = temp_dir("ws");
    let mut cfg = config(&dir);
    cfg.relays = vec![url];
    let s = Signet::with_connector(cfg, Keys::generate(), Arc::new(WsConnector));
    let si = s.sign_in();
    // AwaitingApproval comes only once the relay carries our subscription.
    assert_eq!(wait_for(T, "listening", || si.poll()), SignInEvent::AwaitingApproval);
    assert!(net.hub(RELAY).open_subscriptions() > 1);
    signer.open_app_link(si.app_link());
    let events = drain_sign_in(&si, T);
    assert!(matches!(events.last(), Some(SignInEvent::Attested { .. })), "{events:?}");
    assert_eq!(s.persona(), Some(persona.public_key()));
    let _ = std::fs::remove_dir_all(dir);
}

/// A relay that answers the websocket upgrade with HTTP 503 (damus, on the
/// day): the subscription's status says so, and the failure reads as
/// "unavailable (503)".
#[test]
#[allow(clippy::result_large_err)]
fn a_503_on_the_upgrade_is_reported_as_the_reason() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = tokio_tungstenite::accept_hdr_async(tcp, |_req: &_, _resp| {
                    Err(tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(503)
                        .body(None)
                        .unwrap())
                })
                .await;
            });
        }
    });
    let set = WsConnector.connect(std::slice::from_ref(&url));
    let mut sub = set.subscribe(vec![Filter::new().kind(Kind::GiftWrap)]);
    assert!(matches!(wait_for(T, "eose", || sub.try_recv()), RelayMsg::Eose));
    let SubStatus::Down(reason) = sub.status() else { panic!("{:?}", sub.status()) };
    assert_eq!(RelayFailure::from_down(&reason), RelayFailure::Http(503), "{reason}");
    assert_eq!(RelayFailure::Http(503).phrase(), "unavailable (503)");
}

/// A relay that answers REQ with CLOSED: the status carries its words, also
/// when the CLOSED comes after the EOSE.
#[test]
fn a_closed_frame_is_reported_as_the_status() {
    let rt = tokio::runtime::Runtime::new().unwrap();
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
                        let _ = ws.send(Message::Text(json!(["CLOSED", id, "blocked: no"]).to_string().into())).await;
                    }
                }
            });
        }
    });
    let set = WsConnector.connect(std::slice::from_ref(&url));
    let sub = set.subscribe(vec![Filter::new().kind(Kind::GiftWrap)]);
    let st = wait_for(T, "closed", || matches!(sub.status(), SubStatus::Closed(_)).then(|| sub.status()));
    assert_eq!(st, SubStatus::Closed("blocked: no".into()));
}

/// A relay's CLOSED words cannot carry line breaks, escapes or direction
/// marks into the log or the status: they could forge a whole log line.
#[test]
fn a_closed_text_loses_its_control_and_invisible_characters() {
    let rt = tokio::runtime::Runtime::new().unwrap();
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
                        let text = "no\n[signet] signed in\u{1b}[0m \u{202E}k\u{061C}o\u{2060}\u{FEFF}";
                        let _ = ws.send(Message::Text(json!(["CLOSED", id, text]).to_string().into())).await;
                    }
                }
            });
        }
    });
    let set = WsConnector.connect(std::slice::from_ref(&url));
    let sub = set.subscribe(vec![Filter::new().kind(Kind::GiftWrap)]);
    let st = wait_for(T, "closed", || matches!(sub.status(), SubStatus::Closed(_)).then(|| sub.status()));
    assert_eq!(st, SubStatus::Closed("no[signet] signed in[0m ko".into()));
}

/// Needs the internet: `cargo test -p decented-signet --test ws -- --ignored`.
#[test]
#[ignore]
fn live_public_relays_answer_over_tls() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relays: Vec<String> = decented_signet::DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect();
    let set = WsConnector.connect(&relays);
    let got = rt.block_on(fetch(&*set, vec![Filter::new().kind(Kind::Metadata).limit(3)], Duration::from_secs(15)));
    assert!(!got.is_empty(), "no kind 0 from any default relay");
    assert!(got.iter().all(|e| e.verify().is_ok()));
}

// ─── NIP-42 ─────────────────────────────────────────────────────────────────

const CHALLENGE: &str = "c0ffee-challenge";

/// What an authenticating relay saw, in order: `REQ`, `AUTH <pubkey hex>`.
type Seen = Arc<std::sync::Mutex<Vec<String>>>;

/// What a relay says to the answer to its challenge.
#[derive(Clone, Copy, PartialEq)]
enum Reply {
    /// OK true, if the answer is good.
    Accept,
    /// OK false (damus, on the day: "relay needs serviceUrl to be configured").
    Refuse,
    /// No OK at all.
    Silent,
}

/// When a relay sends its challenge.
#[derive(Clone, Copy, PartialEq)]
enum Challenge {
    /// As the connection opens.
    OnConnect,
    /// With the CLOSED, just before it.
    BeforeClosed,
    /// With the CLOSED, just after it.
    AfterClosed,
}

/// A relay that challenges (when `when` says) and closes every REQ `auth-required`
/// until the client has answered with a good kind 22242 event (or says no to
/// the answer, if `accept` is false). It then serves one stored event.
fn serve_auth(rt: &tokio::runtime::Runtime, stored: nostr::Event, reply: Reply, when: Challenge, challenge: &str) -> (String, Seen) {
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let expect = url.clone();
    let challenge = challenge.to_string();
    rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (log, expect, stored, challenge) = (log.clone(), expect.clone(), stored.clone(), challenge.clone());
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                let auth_frame = || Message::Text(json!(["AUTH", challenge]).to_string().into());
                if when == Challenge::OnConnect {
                    let _ = ws.send(auth_frame()).await;
                }
                let mut authed = false;
                while let Some(Ok(Message::Text(t))) = ws.next().await {
                    let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&t) else { continue };
                    let reply = match a.first().and_then(|v| v.as_str()) {
                        Some("AUTH") => {
                            let ev: nostr::Event = serde_json::from_value(a[1].clone()).unwrap();
                            let tag = |name: &str| ev.tags.iter().find(|t| t.as_slice().first().map(String::as_str) == Some(name)).and_then(|t| t.as_slice().get(1).cloned());
                            let good = ev.kind == Kind::Authentication
                                && ev.verify().is_ok()
                                && tag("challenge").as_deref() == Some(challenge.as_str())
                                && tag("relay").is_some_and(|r| r.trim_end_matches('/') == expect);
                            log.lock().unwrap().push(format!("AUTH {}", ev.pubkey.to_hex()));
                            authed = good && reply == Reply::Accept;
                            if reply == Reply::Silent {
                                continue;
                            }
                            json!(["OK", ev.id.to_hex(), authed, if authed { "" } else { "restricted: no" }])
                        }
                        Some("REQ") => {
                            let id = a[1].as_str().unwrap_or("").to_string();
                            log.lock().unwrap().push("REQ".into());
                            if !authed {
                                if when == Challenge::BeforeClosed {
                                    let _ = ws.send(auth_frame()).await;
                                }
                                let closed = json!(["CLOSED", id, "ERROR: auth-required: requested filter requires authentication"]);
                                if when == Challenge::AfterClosed {
                                    let _ = ws.send(Message::Text(closed.to_string().into())).await;
                                    json!(["AUTH", challenge])
                                } else {
                                    closed
                                }
                            } else {
                                let _ = ws.send(Message::Text(json!(["EVENT", id, stored]).to_string().into())).await;
                                json!(["EOSE", id])
                            }
                        }
                        _ => continue,
                    };
                    let _ = ws.send(Message::Text(reply.to_string().into())).await;
                }
            });
        }
    });
    (url, seen)
}

/// A relay that challenges is answered by a connector built to answer it, and
/// the request it closed `auth-required` is asked again at once, without the
/// subscription ever showing as closed.
#[test]
fn an_auth_challenge_is_answered_and_the_closed_request_asked_again() {
    answered(Challenge::OnConnect);
}

/// The same when the challenge comes with the CLOSED, just before it: the
/// answer is on its way when the CLOSED is read, and the subscription is not
/// shown as closed in between.
#[test]
fn a_challenge_just_before_the_closed_is_answered_without_the_request_showing_as_closed() {
    answered(Challenge::BeforeClosed);
}

/// When the CLOSED comes first and the challenge just after it, the request has
/// been shown as closed already, and stays closed on this connection (the
/// reader's own paced read asks again); the answer is still sent.
#[test]
fn a_request_shown_closed_before_the_challenge_stays_closed() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let keys = Keys::generate();
    let stored = EventBuilder::text_note("x").sign_with_keys(&Keys::generate()).unwrap();
    let (url, seen) = serve_auth(&rt, stored, Reply::Accept, Challenge::AfterClosed, CHALLENGE);
    let set = decented_signet::relay::AuthConnector::new(decented_signet::relay::auth_signer(keys.clone())).connect(std::slice::from_ref(&url));
    let mut sub = set.subscribe(vec![Filter::new().kind(Kind::TextNote)]);
    assert!(matches!(wait_for(T, "eose", || sub.try_recv()), RelayMsg::Eose));
    wait_for(T, "the answer", || (seen.lock().unwrap().len() >= 2).then_some(()));
    std::thread::sleep(Duration::from_millis(300));
    assert!(matches!(sub.status(), SubStatus::Closed(_)), "{:?}", sub.status());
    assert!(sub.try_recv().is_none());
    assert_eq!(seen.lock().unwrap().iter().filter(|s| *s == "REQ").count(), 1);
}

/// A relay that does not answer the answer: the held request is closed, with the
/// relay's own words and one EOSE, soon after (well inside a page wait).
#[test]
fn a_relay_that_never_says_ok_closes_the_held_request_in_time() {
    held_ends_closed(Reply::Silent, Duration::from_secs(8));
}

/// A relay that turns the answer down (damus): closed at once, not after a wait.
#[test]
fn a_relay_that_says_no_closes_the_held_request_at_once() {
    held_ends_closed(Reply::Refuse, Duration::from_secs(2));
}

fn held_ends_closed(reply: Reply, within: Duration) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let stored = EventBuilder::text_note("x").sign_with_keys(&Keys::generate()).unwrap();
    let (url, _seen) = serve_auth(&rt, stored, reply, Challenge::BeforeClosed, CHALLENGE);
    let set = decented_signet::relay::AuthConnector::new(decented_signet::relay::auth_signer(Keys::generate())).connect(std::slice::from_ref(&url));
    let t0 = Instant::now();
    let mut sub = set.subscribe(vec![Filter::new().kind(Kind::TextNote)]);
    assert!(matches!(wait_for(T, "eose", || sub.try_recv()), RelayMsg::Eose));
    assert!(t0.elapsed() < within, "{:?}", t0.elapsed());
    let SubStatus::Closed(why) = sub.status() else { panic!("{:?}", sub.status()) };
    assert!(why.contains("auth-required"), "{why}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(sub.try_recv().is_none(), "one EOSE only");
}

/// A challenge that is empty, too long, or not plain printable text is not
/// signed back.
#[test]
fn an_odd_challenge_is_not_answered() {
    for challenge in ["".to_string(), "x".repeat(300), "tab\there".to_string(), "caf\u{e9}".to_string()] {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let stored = EventBuilder::text_note("x").sign_with_keys(&Keys::generate()).unwrap();
        let (url, seen) = serve_auth(&rt, stored, Reply::Accept, Challenge::OnConnect, &challenge);
        let set = decented_signet::relay::AuthConnector::new(decented_signet::relay::auth_signer(Keys::generate())).connect(std::slice::from_ref(&url));
        let mut sub = set.subscribe(vec![Filter::new().kind(Kind::TextNote)]);
        assert!(matches!(wait_for(T, "eose", || sub.try_recv()), RelayMsg::Eose));
        assert!(matches!(sub.status(), SubStatus::Closed(_)));
        assert!(seen.lock().unwrap().iter().all(|s| !s.starts_with("AUTH")), "answered {challenge:?}");
    }
}

fn answered(when: Challenge) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let keys = Keys::generate();
    let stored = EventBuilder::text_note("held back").sign_with_keys(&Keys::generate()).unwrap();
    let (url, seen) = serve_auth(&rt, stored.clone(), Reply::Accept, when, CHALLENGE);
    let set = decented_signet::relay::AuthConnector::new(decented_signet::relay::auth_signer(keys.clone())).connect(std::slice::from_ref(&url));
    let mut sub = set.subscribe(vec![Filter::new().kind(Kind::TextNote)]);
    // A request held until the answer is in is not answered with an EOSE for the refusal.
    let RelayMsg::Event(ev) = wait_for(T, "the event", || sub.try_recv()) else { panic!("an EOSE came before the event") };
    assert_eq!(ev.id, stored.id);
    assert!(matches!(wait_for(T, "eose", || sub.try_recv()), RelayMsg::Eose));
    assert_eq!(sub.status(), SubStatus::Up);
    assert!(sub.try_recv().is_none());
    assert_eq!(sub.unreachable(), 0);
    // Answered once, as the caller; the request that counted went out after that
    // (the first try may or may not have beaten the answer to the relay).
    let seen = seen.lock().unwrap().clone();
    let auth = format!("AUTH {}", keys.public_key().to_hex());
    assert_eq!(seen.iter().filter(|s| s.starts_with("AUTH")).collect::<Vec<_>>(), [&auth], "{seen:?}");
    assert!(seen.iter().filter(|s| *s == "REQ").count() <= 2 && seen.last().map(String::as_str) == Some("REQ"), "{seen:?}");
}

/// Answering is opt-in: the stock connector leaves the challenge alone and the
/// subscription ends closed, as before.
#[test]
fn the_stock_connector_does_not_answer_an_auth_challenge() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let stored = EventBuilder::text_note("x").sign_with_keys(&Keys::generate()).unwrap();
    let (url, seen) = serve_auth(&rt, stored, Reply::Accept, Challenge::OnConnect, CHALLENGE);
    let set = WsConnector.connect(std::slice::from_ref(&url));
    let mut sub = set.subscribe(vec![Filter::new().kind(Kind::TextNote)]);
    assert!(matches!(wait_for(T, "eose", || sub.try_recv()), RelayMsg::Eose));
    let SubStatus::Closed(why) = sub.status() else { panic!("{:?}", sub.status()) };
    assert!(why.contains("auth-required"), "{why}");
    assert_eq!(*seen.lock().unwrap(), ["REQ".to_string()]);
}

/// A relay that turns the answer down: the request ends closed with the relay's
/// own words, once, and is not sent again.
#[test]
fn a_refused_authentication_leaves_the_request_closed() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let stored = EventBuilder::text_note("x").sign_with_keys(&Keys::generate()).unwrap();
    let (url, seen) = serve_auth(&rt, stored, Reply::Refuse, Challenge::OnConnect, CHALLENGE);
    let set = decented_signet::relay::AuthConnector::new(decented_signet::relay::auth_signer(Keys::generate())).connect(std::slice::from_ref(&url));
    let mut sub = set.subscribe(vec![Filter::new().kind(Kind::TextNote)]);
    assert!(matches!(wait_for(T, "eose", || sub.try_recv()), RelayMsg::Eose));
    let SubStatus::Closed(why) = sub.status() else { panic!("{:?}", sub.status()) };
    assert!(why.contains("auth-required"), "{why}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(seen.lock().unwrap().iter().filter(|s| *s == "REQ").count(), 1);
}
