//! Manual-test driver for decented-signet against a real My Signet (see
//! MANUAL-TEST.md). Not part of the game.
//!
//!   cargo run -p decented-signet --example signet_cli -- --data-dir DIR [--relay URL]... COMMAND
//!
//! Commands: signin | status | refresh | profile | contacts | refresh-contacts | inbox | invite NPUB | book | retract | signout

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::Duration;

use decented_signet::{
    InvitePayload, PairingEvent, RetractEvent, SignInEvent, Signet, SignetConfig,
};
use nostr::{FromBech32, Keys, PublicKey, SecretKey, ToBech32};

const LONG: Duration = Duration::from_secs(300);

fn usage() -> ! {
    eprintln!(
        "usage: signet_cli --data-dir DIR [--relay URL]... \
         (signin|status|refresh|profile|contacts|refresh-contacts|inbox|invite NPUB|book|retract|signout)"
    );
    std::process::exit(2)
}

/// The install's runtime key, a hex secret key in `identity.key`, mode 0600.
fn runtime_key(dir: &Path) -> Keys {
    let path = dir.join("identity.key");
    if let Ok(text) = std::fs::read_to_string(&path)
        && let Ok(sk) = SecretKey::from_hex(text.trim())
    {
        return Keys::new(sk);
    }
    std::fs::create_dir_all(dir).expect("create data dir");
    let keys = Keys::generate();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&path)
        .and_then(|mut f| f.write_all(keys.secret_key().to_secret_hex().as_bytes()))
        .expect("write identity.key");
    keys
}

fn npub(pk: &PublicKey) -> String {
    pk.to_bech32().unwrap_or_default()
}

fn status(s: &Signet) {
    println!("runtime key : {}", npub(&s.runtime_pubkey()));
    match s.persona() {
        None => println!("signed out"),
        Some(p) => {
            println!("persona     : {}", npub(&p));
            println!("name        : {}", s.display_name().unwrap_or_default());
            match s.attestation() {
                Some(a) => println!("attestation : valid until {} (unix)", a.valid_until),
                None => println!("attestation : none"),
            }
            println!("needs refresh: {}", s.needs_refresh(now()));
        }
    }
    if let Some(book) = s.played_with() {
        println!("played with : {} people", book.len());
    }
    if let Some(p) = s.persona() {
        println!(
            "old public notes: {} (retraction offered: {})",
            s.old_public_note_ids(&p).len(),
            s.old_public_note_personas().contains(&p)
        );
    }
    println!(
        "contacts    : {} (grant: {}, stale: {})",
        s.contacts().len(),
        s.has_contacts_grant(),
        s.contacts_stale(now())
    );
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut dir: Option<PathBuf> = None;
    let mut relays = Vec::new();
    let mut rest = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => dir = args.next().map(PathBuf::from),
            "--relay" => relays.push(args.next().unwrap_or_else(|| usage())),
            _ => rest.push(a),
        }
    }
    let dir = dir.unwrap_or_else(|| usage());
    // A made-up game, only for this driver.
    let mut cfg = SignetConfig::new(&dir, "signet-cli", "Signet CLI", None);
    if !relays.is_empty() {
        cfg.relays = relays;
    }
    let s = Signet::open(cfg.clone(), runtime_key(&dir));
    match rest.first().map(String::as_str) {
        Some("signin") => {
            let si = s.sign_in();
            println!(
                "\nOpen this link in the browser where My Signet is unlocked:\n\n{}\n",
                si.app_link()
            );
            println!(
                "(or paste this into My Signet / scan it as a QR:)\n{}\n",
                si.nostrconnect_uri()
            );
            loop {
                match si.poll() {
                    Some(ev) => {
                        println!("-> {ev:?}");
                        if matches!(
                            ev,
                            SignInEvent::Attested { .. }
                                | SignInEvent::AttestationFailed { .. }
                                | SignInEvent::Failed { .. }
                        ) {
                            break;
                        }
                    }
                    None => std::thread::sleep(Duration::from_millis(50)),
                }
            }
            let _ = s.refresh_profile().wait(Duration::from_secs(10));
            status(&s);
        }
        Some("status") => status(&s),
        Some("refresh") => println!("{:?}", s.refresh_attestation().wait(LONG)),
        Some("profile") => println!("{:?}", s.refresh_profile().wait(Duration::from_secs(15))),
        Some("contacts") => {
            let p = s.pair_contacts().unwrap_or_else(|e| panic!("{e}"));
            println!(
                "\nOpen in the browser with My Signet:\n\n{}\n",
                p.links().web
            );
            println!(
                "(Android App Link: {})\n(QR: {})\n",
                p.links().app_link,
                p.links().uri
            );
            loop {
                match p.poll() {
                    Some(PairingEvent::VerificationCode { code }) => {
                        println!("\nType this code into My Signet: {code}\nThen press Enter here.");
                        let _ = std::io::stdin().lock().lines().next();
                        p.confirm();
                    }
                    Some(ev @ (PairingEvent::Paired { .. } | PairingEvent::Failed { .. })) => {
                        println!("-> {ev:?}");
                        break;
                    }
                    Some(ev) => println!("-> {ev:?}"),
                    None => std::thread::sleep(Duration::from_millis(50)),
                }
            }
            for c in s.contacts() {
                println!(
                    "{:?}  {}  {}",
                    c.tier,
                    c.display_name,
                    c.identities.first().map(npub).unwrap_or_default()
                );
            }
        }
        Some("book") => {
            let Some(book) = s.played_with() else {
                return println!("sign in first");
            };
            for e in book.list() {
                println!(
                    "{}  {}  games {}  relays {:?}",
                    e.persona, e.name, e.games, e.inbox_relays
                );
            }
        }
        Some("retract") => {
            let r = s.retract_old_notes();
            println!("(approve the removal in My Signet if it asks)");
            loop {
                match r.poll() {
                    Some(ev @ (RetractEvent::Finished(_) | RetractEvent::Failed { .. })) => {
                        println!("-> {ev:?}");
                        break;
                    }
                    Some(ev) => println!("-> {ev:?}"),
                    None => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        }
        Some("refresh-contacts") => {
            println!("{:?}", s.refresh_contacts().wait(Duration::from_secs(20)));
            for c in s.contacts() {
                println!("{:?}  {}", c.tier, c.display_name);
            }
        }
        Some("inbox") => {
            let inbox = s.inbox();
            println!(
                "listening for invites to {} (Ctrl-C to stop)",
                npub(&s.runtime_pubkey())
            );
            loop {
                if let Some(inv) = inbox.poll() {
                    println!(
                        "{} invited you: code {} (until {})",
                        inv.display_sender(),
                        inv.payload.code,
                        inv.payload.expires_at
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Some("invite") => {
            let who = rest.get(1).unwrap_or_else(|| usage());
            let pk = PublicKey::from_bech32(who)
                .or_else(|_| PublicKey::from_hex(who))
                .expect("npub or hex");
            let Some(entry) = s.played_with().and_then(|b| b.by_persona(&pk)) else {
                println!(
                    "not in the played-with book: invites go only to people you have played with"
                );
                return;
            };
            let payload = InvitePayload {
                host_name: s.display_name().unwrap_or_else(|| "Host".into()),
                code: "TESTAB".into(),
                expires_at: now() + 600,
            };
            println!(
                "{:?}",
                s.send_invite(&entry, payload).wait(Duration::from_secs(20))
            );
            std::thread::sleep(Duration::from_secs(3)); // let the publish leave
        }
        Some("signout") => {
            println!("-> {:?}", s.sign_out().wait(LONG));
            // The old key is retired: a fresh install key for the next persona.
            let _ = std::fs::remove_file(dir.join("identity.key"));
            status(&Signet::open(cfg, runtime_key(&dir)));
        }
        _ => usage(),
    }
}
