# decented-signet: what relays can see

This crate talks to public Nostr relays (by default `relay.damus.io`,
`nos.lol` and `relay.primal.net`). A relay operator sees every event and
subscription sent to it, and the IP address of the client that sent it. This
note lists what that reveals about a player, and what it does not. The code
comments call these the kit rules (rules 1-2 and 5-7 of the privacy rules
for the games this crate serves); this note is their public statement.

## 1. What is never published

- **No persona-to-game link.** The persona signs one kind 30420 attestation
  binding this install's runtime key. It is kept on the phone and sent only
  inside an encrypted channel: the game connection to people in a lobby with
  you, and inside a gift-wrapped invite. It is never published, and nothing the
  crate publishes names a game: no kind, `d`, `t`, `k`, `a` or client tag.
- **No discovery.** Nothing asks a relay "does this npub play?". There is no
  `discover`. You reach people through a room code, a friend link, or an
  in-app invite to someone in your played-with book.
- **No switch to get wrong.** Earlier versions had "Let contacts invite me"
  with withdrawals, tombstones and journals. They are gone.

## 2. What relays do see

- **Sign-in and signing (NIP-46).** Requests from the game and My Signet's
  replies (kind 24133) travel between a per-install client key and the persona
  key. The content is encrypted; the relay sees that the persona key answers a
  client key, when, and the game's IP address. It cannot see what for.
- **The persona's own kind 0 profile**, fetched by npub. It goes over the
  persona connection, the same one as the NIP-46 sign-in (both are the
  persona's own business with My Signet).
- **A played-with person's kind 0**, only when no name is stored, **one lookup
  at a time, never in a batch**: six lookups at once would tell a relay that
  those six play together. Each lookup uses a **fresh, short-lived connection
  of its own**: opened for one REQ for one author, closed at EOSE or after a
  timeout. It never shares a connection with another lookup, with the persona
  connection (your own npub) or with the invite inbox. **What this does not
  hide:** the connections are separate sockets, not separate people. A relay
  that sees the same IP address at nearly the same time can still link a lookup
  to your own npub, and lookups made in the same minute to each other. Spacing
  them out makes that harder to do by accident; it does not make it impossible.
- **The invite inbox.** While the game is open it subscribes for gift wraps
  addressed to the install's runtime key (kind 1059, `#p=R`) on its own
  connection, which carries no persona. A relay sees "R is online now, from IP
  address Y"; nothing there links R to a persona.
- **Invites.** A wrap to R is public. The sender is hidden behind a one-time
  key; the number and timing of wraps to R are visible. The game shows only
  those from someone in the played-with book who is not a blocked contact.
- **Friend links.** A link is plain base64, not encrypted. It carries this
  install's runtime key R (the inbox address), a mailbox secret, one to three
  relays and an expiry. Whoever holds a link can watch gift wraps addressed to
  R, and can read the outer layer of every hello sent to that link: how many,
  when, and roughly how large, but not who sent them. Every link this install
  makes names the same R, so any two of its links can be matched to each
  other. Using someone's link dials the relays that link names (`wss://` only;
  loopback, private and link-local addresses and `localhost` or `.local`
  names are dropped, though a public name that resolves to a private address
  is not caught), and those relays see your IP address. The hello shows your
  persona (the attestation) to the link's owner only. Each live link's mailbox
  is listened to on a connection of its own.
- **Contacts.** Projection fetches go to the relay named in the grant, in their
  own connection. The content is encrypted; the relay sees a grant-scoped tag
  and the IP address.
- **Peers in a game** learn the persona from the attestation in the game
  connection. No relay is involved.

## 3. Not solved

- The same IP address in the same minute still links a persona connection to the
  inbox connection. Separate connections stop a relay seeing an npub and a
  runtime key in one session; they do not hide the network address. Say so in
  the app's privacy note; do not claim more.
- **The played-with book is local.** It holds each person's persona key, runtime
  key, attestation, name, up to three inbox relays and when you played. It is
  one JSON file per persona under `signet/played-with/`, named by a hash of the
  persona key, mode 0600. It is never published or synced. Anyone who can read
  the app's files can read it.
- **Old public notes.** A persona that published an attestation or tombstone
  under an earlier version can take it back. The first open after the upgrade
  keeps, per persona (`old-public-notes.json`):
  - the ids of those events it can find (a stored attestation, journals, and
    the tombstones of unfinished withdrawals);
  - the relays an old withdrawal still owed a tombstone to;
  - the fact that the persona left any old record at all (a journal, a stored
    attestation, a discoverability record), even when no id is known.

  `retract_old_notes` has the persona sign **one kind 5 with `e` tags only**
  (no `a`, `k` or `d` tag, empty content) and sends it to the union of your
  relay list, those owed relays and the built-in default relays (an earlier
  version fell back to those), each on its own connection. The ids are dropped
  only when every relay of that union that could be reached acked and none
  refused; otherwise they stay for another try.

  A persona with no known id (for example one that signed out under the old
  version, whose tombstone this phone never stored) is offered the removal
  too. When the person taps it, the app first asks each of those relays,
  on a fresh connection, for `{authors:[persona], kinds:[30420]}` with no `#d`
  filter, and keeps the events whose `d` tag is this game. That request names
  the persona to those relays, so it is made **only on that tap**, never at
  launch or in the background. The relays already hold the note they are asked
  about, so it adds little; but it is a request by npub.

  Deletion on Nostr is best effort: a relay may ignore it, and anyone who
  copied the note keeps it. A relay that was down when the note went out, or is
  not in the union above, may still serve it. The retraction never runs by
  itself.
- **Runtime keys.** Every sign-in uses a new runtime key. The crate remembers the
  keys earlier sign-ins used and the ones retired at sign-out as hashes
  (`runtime-keys.json`), and refuses to sign in on one of them. A runtime key is
  public to everyone you played with, so the hash only stops the file reading
  as a list of keys. Played-with entries pick up a new key at the next shared
  game, or from an invite whose attestation names a persona in the book.
