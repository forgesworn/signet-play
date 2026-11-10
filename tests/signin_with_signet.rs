//! Sign in with Signet (section 5.1 of the game's spec): the `?auth=1` relay-mode flow against a
//! fake My Signet responder that builds real NIP-59 answers (NIP-44, Schnorr)
//! on the in-memory relay network.

mod support;

use base64::Engine;
use std::sync::Arc;
use std::time::Duration;

use decented_signet::relay::FakeNetwork;
use decented_signet::signin::{BAD_BUNKER, DECLINED, NO_ORIGIN, NO_SIGNER, WRONG_PROFILE};
use decented_signet::{SignIn, SignInEvent, Signet};
use nostr::nips::nip44;
use nostr::util::JsonUtil;
use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp, Url};
use serde_json::{Value, json};
use support::*;

const T: Duration = Duration::from_secs(10);

/// What the fake My Signet puts in (or gets wrong in) its answer.
#[derive(Clone)]
struct Answer {
    /// Signs the auth event; the seal and rumor too unless `seal_key` is set.
    persona: Keys,
    seal_key: Option<Keys>,
    display_name: Option<String>,
    bunker: Option<String>,
    rejected: bool,
    session_tag: Option<String>,
    challenge_tag: Option<String>,
    origin_tag: Option<String>,
    request_id: Option<String>,
    rumor_kind: u16,
    auth_kind: u16,
    /// Seconds in the past (negative: in the future).
    auth_age: i64,
    rumor_age: i64,
    status: String,
    /// Change the auth event's content after signing: its id no longer matches.
    tamper_auth: bool,
    /// Change the wrap's content after signing: its id no longer matches.
    tamper_wrap: bool,
    online_play: Option<&'static str>,
}

impl Answer {
    fn good(persona: &Keys) -> Answer {
        Answer {
            persona: persona.clone(),
            seal_key: None,
            display_name: None,
            bunker: None,
            rejected: false,
            session_tag: None,
            challenge_tag: None,
            origin_tag: None,
            request_id: None,
            rumor_kind: 29999,
            auth_kind: 21236,
            auth_age: 0,
            rumor_age: 0,
            status: "approved".into(),
            tamper_auth: false,
            tamper_wrap: false,
            online_play: None,
        }
    }
    fn name(mut self, n: &str) -> Answer {
        self.display_name = Some(n.into());
        self
    }
    fn bunker_for(mut self, signer: &Keys, secret: &str) -> Answer {
        self.bunker = Some(format!(
            "bunker://{}?relay={}&secret={secret}",
            signer.public_key().to_hex(),
            RELAY.replace(':', "%3A").replace('/', "%2F")
        ));
        self
    }
}

struct Request {
    relay: String,
    challenge: String,
    origin: String,
    session: nostr::PublicKey,
}

fn parse_request(url: &str) -> Request {
    let u = Url::parse(url).unwrap();
    assert_eq!(u.host_str(), Some("mysignet.app"));
    let q = |k: &str| {
        u.query_pairs()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| panic!("no {k} in {url}"))
    };
    assert_eq!(q("auth"), "1");
    assert_eq!(q("name"), "Twang Thang");
    assert_eq!(q("callback"), format!("{}/signet", q("origin")));
    assert!(now().abs_diff(q("t").parse().unwrap()) < 5);
    Request {
        relay: q("relay"),
        challenge: q("challenge"),
        origin: q("origin"),
        session: nostr::PublicKey::from_hex(&q("sessionPubkey")).unwrap(),
    }
}

/// What My Signet does when the person taps Approve (or Deny) on the request
/// link: gift-wrap the answer to the session key, backdated 0-30 s.
fn answer(net: &FakeNetwork, url: &str, a: &Answer) {
    answer_on(net, url, a, RELAY)
}

fn answer_on(net: &FakeNetwork, url: &str, a: &Answer, relay: &str) {
    let req = parse_request(url);
    let t = now();
    let auth_tags = vec![
        Tag::parse([
            "challenge".to_string(),
            a.challenge_tag.clone().unwrap_or(req.challenge.clone()),
        ])
        .unwrap(),
        Tag::parse([
            "origin".to_string(),
            a.origin_tag.clone().unwrap_or(req.origin.clone()),
        ])
        .unwrap(),
    ];
    let mut auth: Event = EventBuilder::new(Kind::Custom(a.auth_kind), "")
        .tags(auth_tags)
        .custom_created_at(Timestamp::from((t as i64 - a.auth_age) as u64))
        .sign_with_keys(&a.persona)
        .unwrap();
    if a.tamper_auth {
        auth.content = "tampered".into();
    }
    let seal_key = a.seal_key.clone().unwrap_or(a.persona.clone());
    let session_tag = a.session_tag.clone().unwrap_or(req.challenge.clone());
    let (tags, content) = if a.rejected {
        (
            vec![
                ["session".to_string(), session_tag],
                ["status".to_string(), "rejected".to_string()],
            ],
            String::new(),
        )
    } else {
        let mut body = json!({
            "type": "signet-auth-response",
            "requestId": a.request_id.clone().unwrap_or(req.challenge.clone()),
            "authEvent": serde_json::to_value(&auth).unwrap(),
        });
        if let Some(n) = &a.display_name {
            body["displayName"] = Value::String(n.clone());
        }
        if let Some(mode) = a.online_play {
            let u = Url::parse(url).unwrap();
            let raw = u
                .query_pairs()
                .find(|(k, _)| k == "app_permission")
                .unwrap()
                .1
                .into_owned();
            let q: Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(raw)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(q["v"], 1);
            assert_eq!(q["permission"], "online-play");
            assert_eq!(
                q["validUntil"].as_u64().unwrap() - q["validFrom"].as_u64().unwrap(),
                90 * 86400
            );
            let mut tags = vec![
                vec!["d".to_string(), q["appId"].as_str().unwrap().into()],
                vec!["p".into(), q["installKey"].as_str().unwrap().into()],
                vec!["valid_from".into(), q["validFrom"].to_string()],
                vec!["valid_until".into(), q["validUntil"].to_string()],
                vec!["v".into(), "1".into()],
                vec!["role".into(), "player".into()],
                vec!["expiration".into(), q["validUntil"].to_string()],
            ];
            match mode {
                "wrong app" => tags[0][1] = "other-game".into(),
                "wrong install" => tags[1][1] = Keys::generate().public_key().to_hex(),
                "wrong expiry" => {
                    tags[3][1] = (t + 100).to_string();
                    tags[6][1] = (t + 100).to_string();
                }
                _ => {}
            }
            let signing_key = if mode == "wrong persona" {
                Keys::generate()
            } else {
                a.persona.clone()
            };
            let event = EventBuilder::new(Kind::Custom(30420), "")
                .tags(tags.into_iter().map(|x| Tag::parse(x).unwrap()))
                .custom_created_at(Timestamp::from(t))
                .sign_with_keys(&signing_key)
                .unwrap();
            body["appPermission"] = if mode == "declined" {
                json!({"v": 1, "permission": "online-play", "status": "declined"})
            } else {
                json!({"v": 1, "permission": "online-play", "status": "approved", "event": event})
            };
            if mode == "tampered" {
                body["appPermission"]["event"]["content"] = json!("changed");
            }
        }
        if let Some(b) = &a.bunker {
            body["bunkerUri"] = Value::String(b.clone());
        }
        (
            vec![
                ["session".to_string(), session_tag],
                ["status".to_string(), a.status.clone()],
            ],
            body.to_string(),
        )
    };
    let rumor = EventBuilder::new(Kind::Custom(a.rumor_kind), content)
        .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
        .custom_created_at(Timestamp::from((t as i64 - a.rumor_age) as u64))
        .build(seal_key.public_key());
    let sealed = nip44::encrypt(
        seal_key.secret_key(),
        &req.session,
        rumor.as_json(),
        nip44::Version::V2,
    )
    .unwrap();
    let seal = EventBuilder::new(Kind::Seal, sealed)
        .custom_created_at(Timestamp::from(t - 9))
        .sign_with_keys(&seal_key)
        .unwrap();
    let eph = Keys::generate();
    let wrapped = nip44::encrypt(
        eph.secret_key(),
        &req.session,
        seal.as_json(),
        nip44::Version::V2,
    )
    .unwrap();
    let mut wrap = EventBuilder::new(Kind::GiftWrap, wrapped)
        .tag(Tag::public_key(req.session))
        .custom_created_at(Timestamp::from(t - 5))
        .sign_with_keys(&eph)
        .unwrap();
    if a.tamper_wrap {
        wrap.content.push('x');
    }
    // A tampered wrap is refused by the relay itself; the flow must also
    // survive anything that reaches it, so go through the hub the way a relay
    // would for honest events and straight to the subscriber otherwise.
    net.hub(relay).publish(&wrap);
}

fn open_with(
    net: &FakeNetwork,
    dir: &std::path::Path,
    runtime: &Keys,
    tweak: impl FnOnce(&mut decented_signet::SignetConfig),
) -> Signet {
    let mut c = config(dir);
    tweak(&mut c);
    Signet::with_connector(c, runtime.clone(), Arc::new(net.clone()))
}

fn listening(si: &SignIn) {
    assert_eq!(
        wait_for(T, "listening", || si.poll()),
        SignInEvent::AwaitingApproval
    );
}

fn failed_reason(events: &[SignInEvent]) -> String {
    match events.last() {
        Some(SignInEvent::Failed { reason }) => reason.clone(),
        other => panic!("expected Failed, got {other:?} in {events:?}"),
    }
}

#[test]
fn a_good_answer_signs_in_with_the_shared_name_and_attests() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    // A hardware-style bunker: its own key (not the persona's), and a one-shot
    // secret it checks. It still signs as the persona.
    let bunker = Keys::generate();
    let signer = FakeMySignet::bunker(
        &net,
        persona.clone(),
        bunker.clone(),
        Some("0123456789abcdef"),
    );
    // The kind 0 says something else: the shared handle outranks it.
    publish_profile(&net, &persona, r#"{"name":"public-name"}"#);
    let dir = temp_dir("sws-good");
    let runtime = Keys::generate();
    let s = open(&net, &dir, &runtime);

    let si = s.sign_in_with_signet();
    assert!(!si.has_qr());
    assert!(si.nostrconnect_uri().is_empty());
    // The link exists only once a relay has confirmed the subscription.
    listening(&si);
    assert!(
        si.app_link()
            .starts_with("https://mysignet.app/?auth=1&challenge=")
    );
    assert!(
        si.app_link()
            .contains("&origin=https%3A%2F%2Fdecented.org&name=Twang+Thang&callback=")
    );
    assert_eq!(parse_request(si.app_link()).relay, RELAY);
    answer(
        &net,
        si.app_link(),
        &Answer::good(&persona)
            .name("  Private Pat  ")
            .bunker_for(&bunker, "0123456789abcdef"),
    );

    let events = drain_sign_in(&si, T);
    assert_eq!(
        events[0],
        SignInEvent::Connected {
            persona: persona.public_key()
        }
    );
    assert_eq!(events[1], SignInEvent::AwaitingSignature);
    let SignInEvent::Attested { info } = &events[2] else {
        panic!("{events:?}")
    };
    assert_eq!(info.persona, persona.public_key());
    assert_eq!(info.runtime, runtime.public_key());
    assert!(s.is_signed_in() && s.has_signer());
    assert!(signer.stats().connects >= 1 && signer.stats().get_public_key >= 1);
    // The persona is the key that signed the challenge, never the bunker's.
    assert_eq!(s.persona(), Some(persona.public_key()));
    assert_ne!(s.persona(), Some(bunker.public_key()));
    assert_eq!(s.display_name().as_deref(), Some("Private Pat"));
    assert!(s.attestation_json().is_some());
    // The attestation and the sign-in are published nowhere.
    let published = net.hub(RELAY).published();
    assert!(
        published.iter().all(|e| e.kind != Kind::Custom(30420)),
        "{published:?}"
    );

    // The answer was awaited on a connection of its own: nothing else the
    // sign-in asked for (the persona's kind 0, say) rode on it.
    let reqs = net.hub(RELAY).reqs();
    let wrap_conn = reqs
        .iter()
        .find(|r| {
            r.filters.iter().any(|f| {
                f.kinds
                    .as_ref()
                    .is_some_and(|k| k.contains(&Kind::GiftWrap))
            })
        })
        .map(|r| r.connection)
        .expect("the answer was subscribed for");
    assert!(
        reqs.iter()
            .filter(|r| r.connection == wrap_conn)
            .all(|r| r.filters.iter().all(|f| f
                .kinds
                .as_ref()
                .is_some_and(|k| k.contains(&Kind::GiftWrap)))),
        "{reqs:?}"
    );

    // Resume: the session, the name and the signer all come back (the
    // restored session reconnects without the one-shot secret).
    drop(si);
    let again = open(&net, &dir, &runtime);
    assert!(again.is_signed_in() && again.has_signer());
    assert_eq!(again.display_name().as_deref(), Some("Private Pat"));
    assert!(again.attestation_json().is_some());
    // One sign-in per runtime key.
    let second = again.sign_in_with_signet();
    assert_eq!(
        failed_reason(&drain_sign_in(&second, T)),
        decented_signet::RUNTIME_KEY_USED
    );
    // Sign-out forgets the handle too.
    let out = again.sign_out().wait(T).unwrap();
    assert!(out.signed_out && out.rotate_runtime_key);
    assert_eq!(again.display_name(), None);
    assert!(!dir.join("signet/signin.json").exists());
    let after = open(&net, &dir, &Keys::generate());
    assert!(!after.is_signed_in());
}

/// Each way an answer can be wrong is dropped, and the flow goes on listening:
/// a good answer from the real persona afterwards still signs in, as the real
/// persona (not the forger that sent the bad one).
#[test]
fn every_bad_answer_is_dropped_and_the_next_good_one_still_signs_in() {
    type Tweak = Box<dyn Fn(&mut Answer)>;
    let cases: Vec<(&str, Tweak)> = vec![
        (
            "wrong challenge",
            Box::new(|a| a.challenge_tag = Some("11".repeat(32))),
        ),
        (
            "wrong origin",
            Box::new(|a| a.origin_tag = Some("https://evil.example".into())),
        ),
        (
            "origin with a trailing slash",
            Box::new(|a| a.origin_tag = Some("https://decented.org/".into())),
        ),
        ("wrong rumor kind", Box::new(|a| a.rumor_kind = 14)),
        ("wrong auth event kind", Box::new(|a| a.auth_kind = 1)),
        (
            "seal is not the auth event's key",
            Box::new(|a| a.seal_key = Some(Keys::generate())),
        ),
        ("stale auth event", Box::new(|a| a.auth_age = 301)),
        ("stale answer", Box::new(|a| a.rumor_age = 301)),
        (
            "auth event from the future",
            Box::new(|a| a.auth_age = -301),
        ),
        ("answer from the future", Box::new(|a| a.rumor_age = -301)),
        ("unknown status", Box::new(|a| a.status = "pending".into())),
        ("bad signature", Box::new(|a| a.tamper_auth = true)),
        (
            "another session",
            Box::new(|a| a.session_tag = Some("22".repeat(32))),
        ),
        (
            "wrong request id",
            Box::new(|a| a.request_id = Some("33".repeat(32))),
        ),
    ];
    for (label, tweak) in cases {
        let net = FakeNetwork::new();
        let real = Keys::generate();
        let forger = Keys::generate();
        let dir = temp_dir("sws-bad");
        let s = open(&net, &dir, &Keys::generate());
        let si = s.sign_in_with_signet();
        listening(&si);

        let mut bad = Answer::good(&forger).name("Forger");
        tweak(&mut bad);
        answer(&net, si.app_link(), &bad);
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            si.poll().is_none(),
            "{label}: the bad answer must not move the sign-in"
        );
        assert!(!s.is_signed_in(), "{label}");

        answer(&net, si.app_link(), &Answer::good(&real).name("Real"));
        let events = drain_sign_in(&si, T);
        assert_eq!(
            events.last(),
            Some(&SignInEvent::NoBunker {
                persona: real.public_key()
            }),
            "{label}: {events:?}"
        );
        assert_eq!(s.persona(), Some(real.public_key()), "{label}");
        assert_eq!(s.display_name().as_deref(), Some("Real"), "{label}");
    }
}

#[test]
fn a_wrap_that_does_not_open_is_dropped() {
    let net = FakeNetwork::new();
    let real = Keys::generate();
    let s = open(&net, &temp_dir("sws-notours"), &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    // A tampered wrap never reaches us (the relay refuses it), and a wrap that
    // is not a seal is dropped: nothing happens.
    let stranger = Keys::generate();
    let mut bad = Answer::good(&stranger);
    bad.tamper_wrap = true;
    answer(&net, si.app_link(), &bad); // refused by the relay: never delivered
    let junk = EventBuilder::new(Kind::GiftWrap, "not a seal")
        .tag(Tag::public_key(parse_request(si.app_link()).session))
        .sign_with_keys(&Keys::generate())
        .unwrap();
    assert!(net.hub(RELAY).publish(&junk));
    std::thread::sleep(Duration::from_millis(150));
    assert!(si.poll().is_none());
    answer(&net, si.app_link(), &Answer::good(&real));
    assert_eq!(
        drain_sign_in(&si, T).last(),
        Some(&SignInEvent::NoBunker {
            persona: real.public_key()
        })
    );
}

#[test]
fn a_denial_ends_the_attempt_but_only_for_this_challenge() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let dir = temp_dir("sws-deny");
    let s = open(&net, &dir, &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    let mut other = Answer::good(&persona);
    other.rejected = true;
    other.session_tag = Some("44".repeat(32));
    answer(&net, si.app_link(), &other);
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        si.poll().is_none(),
        "a denial for another challenge is ignored"
    );
    let mut denied = Answer::good(&persona);
    denied.rejected = true;
    answer(&net, si.app_link(), &denied);
    assert_eq!(failed_reason(&drain_sign_in(&si, T)), DECLINED);
    assert!(!s.is_signed_in());
    assert!(!dir.join("signet/signin.json").exists());
    // And the runtime key is still free for a retry.
    let retry = s.sign_in_with_signet();
    listening(&retry);
    answer(&net, retry.app_link(), &Answer::good(&persona));
    assert!(matches!(
        drain_sign_in(&retry, T).last(),
        Some(SignInEvent::NoBunker { .. })
    ));
}

#[test]
fn a_missing_shared_name_falls_back_to_the_kind_0_then_a_short_npub() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    publish_profile(&net, &persona, r#"{"display_name":"From Kind Zero"}"#);
    let s = open(&net, &temp_dir("sws-kind0"), &Keys::generate());
    let _signer = FakeMySignet::new(&net, persona.clone());
    let si = s.sign_in_with_signet();
    listening(&si);
    answer(
        &net,
        si.app_link(),
        &Answer::good(&persona).bunker_for(&persona, "abcdefgh12345678"),
    );
    assert!(matches!(
        drain_sign_in(&si, T).last(),
        Some(SignInEvent::Attested { .. })
    ));
    wait_for(T, "the kind 0 name", || {
        (s.display_name().as_deref() == Some("From Kind Zero")).then_some(())
    });

    // No shared handle and no kind 0 at all: a short npub.
    let net = FakeNetwork::new();
    let bare = Keys::generate();
    let s = open(&net, &temp_dir("sws-npub"), &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    answer(&net, si.app_link(), &Answer::good(&bare));
    assert!(matches!(
        drain_sign_in(&si, T).last(),
        Some(SignInEvent::NoBunker { .. })
    ));
    assert!(s.display_name().unwrap().starts_with("npub1"));
}

#[test]
fn no_bunker_signs_in_by_name_without_an_attestation() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let dir = temp_dir("sws-nobunker");
    let runtime = Keys::generate();
    let s = open(&net, &dir, &runtime);
    let si = s.sign_in_with_signet();
    listening(&si);
    answer(&net, si.app_link(), &Answer::good(&persona).name("Kid"));
    let events = drain_sign_in(&si, T);
    assert_eq!(
        events,
        vec![
            SignInEvent::Connected {
                persona: persona.public_key()
            },
            SignInEvent::NoBunker {
                persona: persona.public_key()
            },
        ]
    );
    assert!(s.is_signed_in());
    assert!(!s.has_signer());
    assert_eq!(s.persona(), Some(persona.public_key()));
    assert_eq!(s.display_name().as_deref(), Some("Kid"));
    assert!(s.attestation().is_none() && s.attestation_json().is_none());
    assert!(
        !s.needs_refresh(now()),
        "nothing can be refreshed without a signer"
    );
    assert_eq!(
        s.refresh_attestation().wait(T).unwrap().unwrap_err(),
        NO_SIGNER
    );
    // It survives a restart, and a bunker-less persona is not tied to a session file.
    let again = open(&net, &dir, &runtime);
    assert!(again.is_signed_in() && !again.has_signer());
    assert_eq!(again.display_name().as_deref(), Some("Kid"));
    assert_eq!(again.persona(), Some(persona.public_key()));
    // A blank bunkerUri is no bunkerUri.
    let s2 = open(&net, &temp_dir("sws-blankbunker"), &Keys::generate());
    let si2 = s2.sign_in_with_signet();
    listening(&si2);
    let mut a = Answer::good(&persona);
    a.bunker = Some("   ".into());
    answer(&net, si2.app_link(), &a);
    assert!(matches!(
        drain_sign_in(&si2, T).last(),
        Some(SignInEvent::NoBunker { .. })
    ));
}

/// A `bunkerUri` that is there but cannot be used is not "no bunker": the
/// sign-in fails with a plain error, keeps nothing, and leaves the runtime key
/// free for another go.
#[test]
fn a_bunker_uri_that_is_there_but_unusable_fails_the_sign_in() {
    let persona = Keys::generate();
    let good_key = Keys::generate().public_key().to_hex();
    let cases = [
        (
            "a key that is not hex",
            "bunker://nothex?relay=wss%3A%2F%2Frelay.test".to_string(),
        ),
        (
            "a ws:// relay only",
            format!("bunker://{good_key}?relay=ws%3A%2F%2Frelay.test"),
        ),
        ("no relay at all", format!("bunker://{good_key}")),
        (
            "a secret that is too long",
            format!(
                "bunker://{good_key}?relay=wss%3A%2F%2Frelay.test&secret={}",
                "s".repeat(300)
            ),
        ),
        (
            "not a bunker link",
            "https://example.com/bunker".to_string(),
        ),
    ];
    for (label, uri) in cases {
        let net = FakeNetwork::new();
        let dir = temp_dir("sws-unusable");
        let s = open(&net, &dir, &Keys::generate());
        let si = s.sign_in_with_signet();
        listening(&si);
        let mut a = Answer::good(&persona).name("Pat");
        a.bunker = Some(uri);
        answer(&net, si.app_link(), &a);
        let events = drain_sign_in(&si, T);
        assert_eq!(failed_reason(&events), BAD_BUNKER, "{label}: {events:?}");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, SignInEvent::Connected { .. })),
            "{label}"
        );
        assert!(!s.is_signed_in() && !s.runtime_key_used(), "{label}");
        assert!(
            !dir.join("signet/signin.json").exists() && !dir.join("signet/session.json").exists(),
            "{label}: nothing kept"
        );
        // The runtime key is still good: a retry with a usable answer signs in.
        let retry = s.sign_in_with_signet();
        listening(&retry);
        answer(&net, retry.app_link(), &Answer::good(&persona).name("Pat"));
        assert!(
            matches!(
                drain_sign_in(&retry, T).last(),
                Some(SignInEvent::NoBunker { .. })
            ),
            "{label}"
        );
    }
}

/// The bunker's one-shot secret is checked: a wrong one is refused, and
/// nobody is signed in.
#[test]
fn a_bunker_secret_that_is_wrong_signs_nobody_in() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let bunker = Keys::generate();
    let signer = FakeMySignet::bunker(
        &net,
        persona.clone(),
        bunker.clone(),
        Some("rightsecret123456"),
    );
    let dir = temp_dir("sws-secret");
    let s = open(&net, &dir, &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    answer(
        &net,
        si.app_link(),
        &Answer::good(&persona)
            .name("Pat")
            .bunker_for(&bunker, "wrongsecret123456"),
    );
    let events = drain_sign_in(&si, T);
    assert!(
        matches!(events.last(), Some(SignInEvent::Failed { .. })),
        "{events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SignInEvent::Connected { .. }))
    );
    assert!(!s.is_signed_in() && !s.runtime_key_used());
    assert_eq!(
        signer.stats().get_public_key,
        0,
        "a refused connect goes no further"
    );
    assert!(!dir.join("signet/signin.json").exists() && !dir.join("signet/session.json").exists());
}

/// The session key and its subscription go as soon as the answer is judged,
/// not after the bunker connect and the mint (which can take minutes).
#[test]
fn the_session_key_is_let_go_once_the_answer_is_judged() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let dir = temp_dir("sws-letgo");
    let s = open(&net, &dir, &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    let hub = net.hub(RELAY);
    assert_eq!(hub.open_subscriptions(), 1, "only the answer is awaited");
    // A bunker that nobody serves: the connect waits for its timeout.
    let nobody = Keys::generate();
    answer(
        &net,
        si.app_link(),
        &Answer::good(&persona)
            .name("Pat")
            .bunker_for(&nobody, "abcdefgh12345678"),
    );
    wait_for(T, "the bunker connect to start", || {
        hub.reqs()
            .iter()
            .any(|r| {
                r.filters.iter().any(|f| {
                    f.kinds
                        .as_ref()
                        .is_some_and(|k| k.contains(&Kind::NostrConnect))
                })
            })
            .then_some(())
    });
    // Only the bunker's reply subscription is open: the answer's is closed.
    assert_eq!(hub.open_subscriptions(), 1);
    assert!(
        si.poll().is_none(),
        "still connecting: {:?}",
        s.is_signed_in()
    );
    drop(si);
}

/// Only the relay that opened is listened on (and named in the link), on a
/// connection that carries nothing else; the others are not even dialled once
/// one has opened.
#[test]
fn the_answer_is_awaited_only_on_the_relay_that_opened() {
    const SECOND: &str = "wss://second.test";
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open_with(&net, &temp_dir("sws-relays"), &Keys::generate(), |c| {
        c.relays = vec![RELAY.into(), SECOND.into(), "ws://not-wss.test".into()]
    });
    let si = s.sign_in_with_signet();
    listening(&si);
    assert_eq!(parse_request(si.app_link()).relay, RELAY);
    assert_eq!(net.hub(RELAY).open_subscriptions(), 1);
    assert_eq!(
        net.hub(SECOND).reqs().len(),
        0,
        "not tried once the first opened"
    );
    assert_eq!(net.hub("ws://not-wss.test").reqs().len(), 0);
    answer(&net, si.app_link(), &Answer::good(&persona).name("Pat"));
    assert!(matches!(
        drain_sign_in(&si, T).last(),
        Some(SignInEvent::NoBunker { .. })
    ));
    assert_eq!(s.persona(), Some(persona.public_key()));
}

const A: &str = "wss://a.test";
const B: &str = "wss://b.test";
const C: &str = "wss://c.test";

/// 503 on A, CLOSED on B, C fine: C is used and named in the link, and the
/// answer on C signs in.
#[test]
fn a_relay_that_is_down_or_refuses_is_skipped_and_the_one_that_opens_is_named() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    net.hub(A)
        .set_failing("HTTP error: 503 Service Unavailable");
    net.hub(B).set_closing(Some("blocked: not for you"));
    let s = open_with(&net, &temp_dir("sws-skip"), &Keys::generate(), |c| {
        c.signin_relays = vec![A.into(), B.into()];
        c.relays = vec![C.into()];
    });
    let si = s.sign_in_with_signet();
    assert_eq!(si.app_link(), "", "no link before a relay has opened");
    listening(&si);
    assert_eq!(parse_request(si.app_link()).relay, C);
    assert_eq!(net.hub(A).open_subscriptions(), 0);
    assert_eq!(net.hub(B).open_subscriptions(), 0);
    assert_eq!(net.hub(C).open_subscriptions(), 1);
    // Tried in order, each on its own connection.
    let conn = |h: &str| net.hub(h).reqs()[0].connection;
    assert!(conn(A) < conn(B) && conn(B) < conn(C));
    // My Signet answers on the relay the link names.
    answer_on(&net, si.app_link(), &Answer::good(&persona).name("Pat"), C);
    assert!(matches!(
        drain_sign_in(&si, T).last(),
        Some(SignInEvent::NoBunker { .. })
    ));
}

/// The defaults come first even when the player lists them last, and a
/// player's relay already among the defaults is not tried twice.
#[test]
fn the_defaults_are_tried_before_the_players_own_relays() {
    let net = FakeNetwork::new();
    net.hub(A).set_offline(true);
    net.hub(B).set_offline(true);
    let s = open_with(&net, &temp_dir("sws-order"), &Keys::generate(), |c| {
        c.signin_relays = vec![A.into(), "WSS://B.test/".into()];
        c.relays = vec![C.into(), B.into(), A.into()];
    });
    let si = s.sign_in_with_signet();
    listening(&si);
    assert_eq!(parse_request(si.app_link()).relay, C);
    for h in [A, B, C] {
        assert_eq!(net.hub(h).reqs().len(), 1, "{h} once");
    }
}

/// Nothing opens: a neutral headline, then every relay with its reason, and
/// no link ever.
#[test]
fn when_no_relay_opens_the_failure_names_each_one_and_no_link_goes_out() {
    let net = FakeNetwork::new();
    net.hub(A).set_offline(true);
    net.hub(B)
        .set_failing("HTTP error: 503 Service Unavailable");
    net.hub(C).set_closing(Some("restricted"));
    let s = open_with(&net, &temp_dir("sws-allfail"), &Keys::generate(), |c| {
        c.signin_relays = vec![A.into(), B.into()];
        c.relays = vec![C.into()];
    });
    let si = s.sign_in_with_signet();
    let events = drain_sign_in(&si, T);
    assert!(
        !events.contains(&SignInEvent::AwaitingApproval),
        "{events:?}"
    );
    assert_eq!(
        failed_reason(&events),
        "No relay would carry the sign-in\n\
         a.test: couldn't connect · b.test: unavailable (503) · c.test: closed the request"
    );
    assert_eq!(si.app_link(), "");
    assert!(!s.is_signed_in());
}

/// A relay that takes the connection but is slow to say EOSE is not held
/// against; the first one to confirm is used, and the rest are left alone.
#[test]
fn a_connected_relay_that_is_slow_to_eose_still_carries_the_sign_in() {
    let net = FakeNetwork::new();
    net.hub(A).set_mute(true);
    let s = open_with(&net, &temp_dir("sws-mute"), &Keys::generate(), |c| {
        c.signin_relays = vec![A.into(), B.into()];
        c.signin_open_wait = Duration::from_millis(300);
    });
    let si = s.sign_in_with_signet();
    listening(&si);
    assert_eq!(parse_request(si.app_link()).relay, A);
    assert_eq!(net.hub(B).reqs().len(), 0);
}

/// After the link has gone out the relay can CLOSE the subscription: the
/// attempt ends at once, naming the relay, and never moves to another.
#[test]
fn a_relay_that_closes_after_the_link_ends_the_attempt_and_names_itself() {
    let net = FakeNetwork::new();
    let s = open_with(
        &net,
        &temp_dir("sws-closed-after"),
        &Keys::generate(),
        |c| {
            c.signin_relays = vec![A.into(), B.into()];
        },
    );
    let si = s.sign_in_with_signet();
    listening(&si);
    net.hub(A).close_all("rate-limited");
    let reason = failed_reason(&drain_sign_in(&si, T));
    assert!(
        reason.contains("a.test closed the sign-in request"),
        "{reason}"
    );
    assert_eq!(net.hub(B).reqs().len(), 0, "never moves after the link");
}

/// With nothing arriving, the timeout text keeps its wording and says which
/// relay it was listening on, and whether that relay dropped.
#[test]
fn the_timeout_says_which_relay_it_was_listening_on() {
    let net = FakeNetwork::new();
    let s = open_with(
        &net,
        &temp_dir("sws-timeout-relay"),
        &Keys::generate(),
        |c| {
            c.signin_relays = vec![A.into()];
            c.pairing_timeout = Duration::from_millis(400);
        },
    );
    let si = s.sign_in_with_signet();
    let reason = failed_reason(&drain_sign_in(&si, T));
    assert!(reason.starts_with("My Signet didn't answer."), "{reason}");
    assert!(reason.contains("It was listening on a.test."), "{reason}");

    let s = open_with(
        &net,
        &temp_dir("sws-timeout-drop"),
        &Keys::generate(),
        |c| {
            c.signin_relays = vec![B.into()];
            c.pairing_timeout = Duration::from_millis(600);
        },
    );
    let si = s.sign_in_with_signet();
    listening(&si);
    net.hub(B).drop_connections("Connection reset");
    let reason = failed_reason(&drain_sign_in(&si, T));
    assert!(reason.contains("didn't answer"), "{reason}");
    assert!(
        reason.contains("listening on b.test, which dropped the connection"),
        "{reason}"
    );
}

/// A persona that signed in without a bunker has no session, and starting a
/// contacts pairing or an invite inbox is refused for it.
#[test]
fn a_no_bunker_persona_runs_no_contacts_pairing_and_no_invite_inbox() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let dir = temp_dir("sws-nobunker-services");
    let s = open(&net, &dir, &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    answer(&net, si.app_link(), &Answer::good(&persona).name("Kid"));
    assert!(matches!(
        drain_sign_in(&si, T).last(),
        Some(SignInEvent::NoBunker { .. })
    ));
    assert!(s.pair_contacts().is_err());
    let before = net.hub(RELAY).reqs().len();
    let inbox = s.inbox();
    std::thread::sleep(Duration::from_millis(100));
    assert!(inbox.poll().is_none());
    assert_eq!(
        net.hub(RELAY).reqs().len(),
        before,
        "no inbox subscription was opened"
    );
}

#[test]
fn an_over_long_or_dirty_name_is_cleaned_and_trimmed() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open(&net, &temp_dir("sws-long"), &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    let long = format!("  {}\u{202e}\n", "n".repeat(100));
    answer(&net, si.app_link(), &Answer::good(&persona).name(&long));
    drain_sign_in(&si, T);
    assert_eq!(s.display_name().unwrap(), "n".repeat(64));
    // Nothing printable left: no shared name, a short npub.
    let s = open(&net, &temp_dir("sws-blank"), &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    answer(
        &net,
        si.app_link(),
        &Answer::good(&persona).name(" \u{200b}\n "),
    );
    drain_sign_in(&si, T);
    assert!(s.display_name().unwrap().starts_with("npub1"));
}

#[test]
fn a_bunker_that_answers_as_someone_else_signs_nobody_in() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let other = Keys::generate();
    let _signer = FakeMySignet::new(&net, other.clone());
    let dir = temp_dir("sws-wrong");
    let s = open(&net, &dir, &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    // The challenge is signed by `persona`, the bunker belongs to `other`.
    answer(
        &net,
        si.app_link(),
        &Answer::good(&persona)
            .name("Mallory")
            .bunker_for(&other, "abcdefgh12345678"),
    );
    assert_eq!(failed_reason(&drain_sign_in(&si, T)), WRONG_PROFILE);
    assert!(!s.is_signed_in());
    assert!(!dir.join("signet/signin.json").exists() && !dir.join("signet/session.json").exists());
}

#[test]
fn no_answer_times_out_and_a_retry_starts_a_fresh_request() {
    let net = FakeNetwork::new();
    let s = open_with(&net, &temp_dir("sws-timeout"), &Keys::generate(), |c| {
        c.pairing_timeout = Duration::from_millis(400)
    });
    let si = s.sign_in_with_signet();
    let events = drain_sign_in(&si, T);
    assert!(
        failed_reason(&events).contains("didn't answer"),
        "{events:?}"
    );
    assert!(!s.is_signed_in());
    let retry = s.sign_in_with_signet();
    wait_for(T, "the retry's link", || {
        (!retry.app_link().is_empty()).then_some(())
    });
    assert_ne!(si.app_link(), retry.app_link());
    let (a, b) = (
        parse_request(si.app_link()),
        parse_request(retry.app_link()),
    );
    assert_ne!(a.challenge, b.challenge);
    assert_ne!(a.session, b.session);
    // Dropping a waiting attempt stops listening.
    drop(retry);
}

#[test]
fn without_an_origin_or_a_relay_it_says_so_at_once() {
    let net = FakeNetwork::new();
    let s = open_with(&net, &temp_dir("sws-noorigin"), &Keys::generate(), |c| {
        c.signin_origin = None
    });
    assert_eq!(
        failed_reason(&drain_sign_in(&s.sign_in_with_signet(), T)),
        NO_ORIGIN
    );
    let s = open_with(&net, &temp_dir("sws-slash"), &Keys::generate(), |c| {
        c.signin_origin = Some("https://decented.org/".into())
    });
    assert_eq!(
        failed_reason(&drain_sign_in(&s.sign_in_with_signet(), T)),
        NO_ORIGIN
    );
    let s = open_with(&net, &temp_dir("sws-norelay"), &Keys::generate(), |c| {
        c.relays = vec![]
    });
    assert!(failed_reason(&drain_sign_in(&s.sign_in_with_signet(), T)).contains("relay"));
}

#[test]
fn the_old_nostrconnect_pairing_still_works_beside_it() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let dir = temp_dir("sws-other-way");
    let s = open(&net, &dir, &Keys::generate());
    let _signer = sign_in_as(&net, &s, &persona);
    assert!(s.has_signer());
    assert!(s.attestation_json().is_some());
    assert!(
        !dir.join("signet/signin.json").exists(),
        "a nostrconnect sign-in records nothing extra"
    );
}

#[test]
fn combined_approval_attests_without_a_bunker_and_survives_reload() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let runtime = Keys::generate();
    let dir = temp_dir("sws-combined");
    let s = open(&net, &dir, &runtime);
    let si = s.sign_in_with_signet();
    listening(&si);
    let mut a = Answer::good(&persona).name("Pat");
    a.online_play = Some("approved");
    answer(&net, si.app_link(), &a);
    let events = drain_sign_in(&si, T);
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(
        matches!(&events[1], SignInEvent::Attested { info } if info.persona == persona.public_key() && info.runtime == runtime.public_key())
    );
    assert!(s.is_signed_in() && !s.has_signer());
    drop(si);
    drop(s);
    let reloaded = open(&net, &dir, &runtime);
    assert!(reloaded.is_signed_in() && !reloaded.has_signer());
    assert!(reloaded.attestation().is_some());
}

#[test]
fn combined_decline_keeps_sign_in_and_has_no_statement() {
    let net = FakeNetwork::new();
    let persona = Keys::generate();
    let s = open(&net, &temp_dir("sws-combined-declined"), &Keys::generate());
    let si = s.sign_in_with_signet();
    listening(&si);
    let mut a = Answer::good(&persona);
    a.online_play = Some("declined");
    answer(&net, si.app_link(), &a);
    assert!(matches!(
        drain_sign_in(&si, T).last(),
        Some(SignInEvent::NoBunker { .. })
    ));
    assert!(s.is_signed_in() && s.attestation().is_none());
}

#[test]
fn combined_statement_must_match_this_app_install_persona_and_requested_expiry() {
    for mode in [
        "wrong app",
        "wrong install",
        "wrong persona",
        "wrong expiry",
        "tampered",
    ] {
        let net = FakeNetwork::new();
        let persona = Keys::generate();
        let s = open(&net, &temp_dir("sws-combined-invalid"), &Keys::generate());
        let si = s.sign_in_with_signet();
        listening(&si);
        let mut bad = Answer::good(&persona);
        bad.online_play = Some(mode);
        answer(&net, si.app_link(), &bad);
        std::thread::sleep(Duration::from_millis(80));
        assert!(si.poll().is_none() && !s.is_signed_in(), "{mode}");
        let mut good = Answer::good(&persona);
        good.online_play = Some("approved");
        answer(&net, si.app_link(), &good);
        assert!(
            matches!(
                drain_sign_in(&si, T).last(),
                Some(SignInEvent::Attested { .. })
            ),
            "{mode}"
        );
    }
}
