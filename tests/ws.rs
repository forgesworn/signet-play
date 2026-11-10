//! The live websocket relay client, against a loopback websocket server that
//! fronts the in-memory relay (no internet). The relay client's own websocket
//! tests live in the `fray-relay-client` crate.

mod support;

use std::sync::Arc;
use std::time::Duration;

use decented_signet::relay::{Connector, FakeNetwork, RelayMsg, SubStatus, WsConnector};
use decented_signet::signin::RelayFailure;
use decented_signet::{SignInEvent, Signet};
use futures_util::{SinkExt, StreamExt};
use nostr::{Filter, Keys, Kind};
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
