# signet-play

The Rust crate `decented-signet`: My Signet integration for a game install,
platform-neutral. It names no game: the app id, display name and sign-in
callback come from `SignetConfig`.

What it does:

- **Sign-in** as a persona over NIP-46 (`nostrconnect://`, the My Signet App
  Link, and a persisted session that resumes offline), and the "Sign in with
  Signet" relay-mode flow.
- **Attestation**: the persona signs one kind 30420 event binding this
  install's runtime key. It is kept on the device, never published, and is
  sent only inside an encrypted channel.
- **Profile**: the persona's kind 0 name, cached, and other people's names one
  lookup at a time.
- **Contacts** from the contacts-v2 app grant, with the verification code the
  person types into My Signet, then the encrypted projection, cached.
- **The played-with book**: who you have shared a game with, kept locally, one
  file per persona.
- **Invites** as NIP-59 gift wraps, only to people in that book, and friend
  links (using `decented-invite`).
- **Old public notes**: taking back what an earlier version published.
- Explicit public result sharing, behind its own signing permission.

The relay client now lives in the `fray-relay-client` crate and is re-exported here as `relay`.

The API is synchronous and never blocks. Work runs on the crate's own tokio
runtime and long operations return a handle with `poll()`. The persona key
never reaches this crate.

Comments in the code refer to "the kit rules". They are the privacy rules for
the games this crate serves; `PRIVACY.md` states what they mean for relays.

## Dependencies pinned by git revision

- `decented-relays` (package `fray-relays`), from
  [forgesworn/fray](https://github.com/forgesworn/fray) at revision
  `4943413bb86a329c3ad9cc3180c02fd9186ef2ce`.
- `decented-invite`, from
  [forgesworn/friend-link-kit](https://github.com/forgesworn/friend-link-kit)
  at revision `91e9e2a53713805a8d50e59b3746815dbb0045d6`.

## Tests

```
cargo test
```

The tests run against an in-memory relay network and local loopback servers.
`tests/no_game_names.rs` fails if a game name appears in library code outside
test modules.

To try the crate against the real My Signet web app, follow `MANUAL-TEST.md`.
It uses the `signet_cli` example; its usage line is at the top of
`examples/signet_cli.rs`.

## Further reading

- `PRIVACY.md`: what relays can and cannot see.
- `MANUAL-TEST.md`: a walk-through against My Signet.
- `NOTICE`: where parts of the code came from, and their licences.

## Licence

MIT. See `LICENSE`.
