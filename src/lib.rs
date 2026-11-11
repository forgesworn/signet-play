//! # decented-signet
//!
//! My Signet integration for a game install, platform-neutral. Private play
//! never publishes a persona-to-game link (kit rules 1-2 and 5-7).
//! Explicit public result sharing is isolated in [`sharing`], requiring fresh
//! public status and a separate, approved conditional signing permission:
//!
//! - **Sign-in** as a persona over NIP-46 (`nostrconnect://`, the My Signet
//!   App Link, a persisted session that resumes offline): [`Signet::sign_in`].
//! - **Attestation**: the persona signs one kind 30420 event binding this
//!   install's runtime key (90 days, re-minted under 7 days left), kept on the
//!   phone only; peers check it with [`verify_attestation`] when it arrives
//!   inside an encrypted channel. A new runtime key is used at every sign-in.
//! - **Profile**: the persona's kind 0 name, cached ([`Signet::refresh_profile`]);
//!   other personas' names one lookup at a time ([`Signet::lookup_name`]).
//! - **Contacts** from the contacts-v2 app grant: [`Signet::pair_contacts`]
//!   (with the verification code the person types into My Signet), then the
//!   encrypted kind 30078 projection, cached ([`ContactBook`]).
//! - **The played-with book** ([`PlayedWithBook`]): who you have shared a game
//!   with, kept locally, one file per persona.
//! - **Invites** only to people in that book: [`Signet::send_invite`] a NIP-59
//!   gift wrap to the entry's runtime key; receive through [`InviteInbox`],
//!   which has its own relay connection and the book-and-blocks policy.
//! - **Old public notes**: [`Signet::old_public_note_ids`] and
//!   [`Signet::retract_old_notes`] take back what an earlier version published.
//!
//! The crate names no game: the app id, name and sign-in callback come from
//! [`SignetConfig`].
//!
//! The API is synchronous and never blocks: work runs on the crate's own tokio
//! runtime; long operations hand back a handle with `poll()`.
//! The persona key never reaches this crate; the runtime key is the caller's
//! (`nostr::Keys`, the same key the transport uses).

pub mod attestation;
pub mod contacts;
/// The contacts-v2 wire format, from the `signet-contacts` crate. The module
/// path is kept so existing `contacts_wire::…` paths resolve as before.
pub use signet_contacts as contacts_wire;
pub mod invite;
mod legacy;
/// The NIP-46 client, from the `signet-nip46-client` crate. The module path is
/// kept so existing `nip46::…` paths resolve as before.
pub use signet_nip46_client as nip46;
pub mod played_with;
/// Talking to Nostr relays, from the `fray-relay-client` crate. The module
/// path is kept so existing `relay::…` paths resolve as before.
pub use fray_relay_client as relay;
pub mod retract;
mod signet;
mod store;

pub use attestation::{AttestationError, PersonaInfo, needs_refresh, verify_attestation};
pub use contacts::{Contact, ContactBook, ContactsSync, PairingLinks, Tier};
pub use decented_invite::{FriendLink, InviteError as FriendLinkError};
pub use invite::{Invite, InviteError, InvitePayload};
pub use played_with::{BookError, PlayedWithBook, PlayedWithEntry};
pub use signet::permission;
pub use signet::signin;
pub use signet::sharing;
pub use signet::{
    FRIEND_REPLY_RUMOR_KIND, FriendEvent, FriendHello, LiveFriendLink, MAX_HELLOS_PER_LINK, MAX_HELLOS_PER_SENDER,
    MAX_LIVE_LINKS, MAX_PENDING, PendingFriendLink,
    ContactsPairing, DEFAULT_RELAYS, InviteInbox, PAIRING_LINK_MAX_AGE_SECS, PairingEvent,
    PermissionAsk, PermissionEvent, RUNTIME_KEY_USED, RelayOutcome, RetractEvent, RetractReport, Retraction, SignIn, SignInEvent,
    SignInRefusal, SignOutOutcome, Signet, SignetConfig, normalize_relay_url,
    pairing_link_is_stale,
};

/// The crate's runtime: the relay client's own, so the process has one.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    fray_relay_client::runtime()
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Characters that draw nothing or reorder text: controls, bidi controls,
/// zero-width and joiner characters, line and paragraph separators, the
/// invisible operators, and the byte-order mark. The class of
/// `decented_invite`'s name sanitiser.
pub(crate) fn hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// The result of a background operation, delivered once: the relay client's
/// handle, so this path and `relay::Task` name one type.
pub use fray_relay_client::Task;

/// The My Signet App Link for a `nostrconnect://` URI:
/// `https://mysignet.app/?nostrconnect=<uri>&callback=<callback>`, each value
/// form-urlencoded (what `URLSearchParams.get` decodes back exactly).
///
/// My Signet only honours an `https://` (or loopback `http://`) callback;
/// anything else, e.g. a custom `game://signin` scheme, is dropped silently after
/// approval (the pairing still completes over the relay). `None` omits it.
pub fn mysignet_app_link(nostrconnect_uri: &str, callback: Option<&str>) -> String {
    let mut url = nostr::Url::parse("https://mysignet.app/").expect("static URL");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("nostrconnect", nostrconnect_uri);
        if let Some(cb) = callback.filter(|c| !c.is_empty()) {
            q.append_pair("callback", cb);
        }
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_link_round_trips_the_inner_uri() {
        let inner = "nostrconnect://ab?relay=wss%3A%2F%2Frelay.damus.io&secret=00&name=Twang+Thang&metadata=%7B%22name%22%3A%22Twang+Thang%22%7D";
        let link = mysignet_app_link(inner, Some("twangthang://signin"));
        assert!(link.starts_with(
            "https://mysignet.app/?nostrconnect=nostrconnect%3A%2F%2Fab%3Frelay%3Dwss%253A"
        ));
        assert!(link.ends_with("&callback=twangthang%3A%2F%2Fsignin"));
        let u = nostr::Url::parse(&link).unwrap();
        let got: Vec<(String, String)> =
            u.query_pairs().map(|(k, v)| (k.into(), v.into())).collect();
        assert_eq!(got[0], ("nostrconnect".into(), inner.into()));
        assert_eq!(got[1], ("callback".into(), "twangthang://signin".into()));
        assert!(!mysignet_app_link(inner, None).contains("callback"));
    }
}
