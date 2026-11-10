# decented-signet: manual test against the web My Signet

Signs a desktop build in as a My Signet persona, mints the runtime-key
attestation (kept on the machine, never published), pairs contacts, and sends an
invite between two installs that have played together. Uses the `signet_cli`
example (no game UI needed); a game drives the same API. The example is a made-up
game called "Signet CLI" with the app id `signet-cli` and no sign-in callback.

Use the PIN `123456` for every test persona.

## 0. Setup

1. Build once:
   ```
   cargo build --example signet_cli
   ```
   Every command below is `cargo run --example signet_cli -- --data-dir <DIR> <COMMAND>`.
   Shorthand here: `cli A <COMMAND>` = data dir `/tmp/signet-a`, `cli B <COMMAND>` = `/tmp/signet-b`.
2. Browser: one browser profile per test persona (separate storage). Profile
   "Persona A" for install A, "Persona B" for install B.
3. In each profile open `https://mysignet.app`, create (or restore) a test
   identity, set the PIN to `123456`, and make sure a **persona** exists.
4. Relays: defaults are `wss://relay.damus.io`, `wss://nos.lol`,
   `wss://relay.primal.net`. To use others add `--relay wss://…` (repeatable)
   to every command, the same on both installs.

## 1. Sign in (install A)

1. Run `cli A signin`. It prints:
   - a `https://mysignet.app/?nostrconnect=…` link (no callback: the example has none)
   - the raw `nostrconnect://…` URI (for QR / paste)
   - `-> AwaitingApproval`
2. Once `-> AwaitingApproval` shows (the relays are listening), copy the
   `https://mysignet.app/?nostrconnect=…` link into the address bar of
   the "Persona A" browser profile. Unlock with `123456` if asked.
3. My Signet shows **Connection Request** for **Signet CLI**, with the relay
   and a persona picker. Pick the test persona (not the real identity). Approve.
4. Expected in the terminal within a few seconds:
   - `-> Connected { persona: … }`
   - `-> AwaitingSignature`
5. My Signet now asks to sign an event (kind 30420, unclassified, so it asks
   every time). Tap **Approve once** (or **Allow always for Signet CLI**).
   Do this within 2 minutes and keep the My Signet tab open: it only answers
   while it is serving (opening a nostrconnect link starts a 2-minute window).
6. Expected: `-> Attested { info: … }`, then a status block with the persona
   npub, its name (kind 0 `display_name`/`name`, else a short npub) and
   `attestation : valid until …`.
7. Known and expected: My Signet only follows https callbacks, so a game's
   custom-scheme callback does not bounce back; it stays on its home screen.
   Pairing still completes.
8. Nothing is published: `nak req -k 30420 <relay>` (or any relay viewer) shows no
   attestation for the persona, and the file `/tmp/signet-a/signet/attestation.json`
   is the only copy.

Failure checks:
- Press **Deny** on the Connection Request: My Signet sends no reply; the
  terminal shows `Failed { reason: "My Signet didn't answer…" }` after the
  pairing timeout (3 minutes). Nothing is saved (`/tmp/signet-a/signet/session.json`
  absent).
- Deny the 30420 signature: `AttestationFailed { reason: "My Signet said no (user denied)." }`;
  `cli A status` shows signed in, `attestation : none`, `needs refresh: true`.

## 2. Resume and refresh

1. `cli A status` (works offline): same persona and attestation, no prompt.
2. `cli A refresh`: My Signet (tab open, unlocked) gets a `connect` (silent)
   and one signing prompt; approve. Expected `Ok(PersonaInfo { … })`.
3. Files in `/tmp/signet-a/signet/` are mode 0600; `session.json` holds the NIP-46
   client key, the signer pubkey, relays and the persona pubkey, never the
   persona's secret.

## 3. Contacts (install A)

1. In My Signet ("Persona A"), add Persona B as a contact (paste B's npub on
   the persona card) and set a tier (Kith). Get B's npub from step 5.1 first,
   or come back to this step.
2. `cli A contacts`. Open the printed `https://mysignet.app/?pair=1&…` link in
   the "Persona A" profile.
3. My Signet shows the contacts grant screen for **Signet CLI**: choose the
   directory, keep the ticked capabilities (directory, tier, blocks), approve.
4. The terminal prints `Type this code into My Signet: 123 456` (your code
   differs). Type it into My Signet. Press Enter in the terminal **only after
   My Signet says the code matched**; if it says it did not, press Ctrl-C and
   start again (the game cannot see My Signet's verdict).
5. Expected: `-> Paired { sync: Updated { contacts: N } }` and the list, Kin
   first, then Kith, then Ken; blocked contacts never listed. `Unchanged` means
   My Signet has not published the list yet: run `cli A refresh-contacts`.
6. Block someone in My Signet, `cli A refresh-contacts`: they disappear.

## 4. Second install (B)

1. Repeat section 1 with `cli B signin` in the "Persona B" profile.
2. In "Persona B", add Persona A as a **Kith** or **Kin** contact, then run
   section 3 with `cli B contacts`.

## 5. Invite A -> B (people who have played together)

There is no lookup: an invite goes only to someone in the played-with book,
and only they can receive it. The CLI cannot play a game, so seed the book
by hand: run both installs' `status`, then in a scratch Rust test or a
`cargo test` run, see `tests/invites.rs` (`meet`) for how
a game does it, with `PlayedWithBook::record` (the other install's
`attestation_json()` and runtime key, name and `inbox_relays()`).

1. `cli B status` prints B's persona npub and the size of its book.
2. Terminal 1: `cli B inbox` (leave running).
3. Terminal 2: `cli A book` lists who A has played with, then
   `cli A invite <npub of Persona B>`. Expected `Ok(())`; an npub that is not in
   the book prints "not in the played-with book".
4. Terminal 1 within a few seconds: `<name> invited you: code TESTAB …`.
5. Policy checks:
   - Someone who is not in B's book sends an invite: nothing shows, nothing is
     logged on the sender's side (it cannot tell).
   - Block A in "Persona B", then `cli B refresh-contacts` (an open inbox also
     re-reads the contacts every 5 minutes): nothing shows.

## 6. Old public notes and sign out

1. A phone upgraded from a version that published the attestation shows
   `old public notes: N` in `status`. `cli A retract` asks My Signet to sign
   **one kind 5 with `e` tags only**; approve. It prints each relay's answer
   (`Acked`, `Refused`, `Unreachable`) for your relays, any relay an old
   withdrawal still owed, and the three built-in defaults, then `Finished`. The
   ids are dropped once no relay refused, every reachable one acked and at
   least one took it. A persona the upgrade found any old record for (but no
   id) is offered it too: before signing, the tap looks up its kind 30420 notes
   on each relay (no `#d`). It never runs by itself.
2. `cli B signout`: nothing is sent and My Signet is not asked for anything.
   Expected `SignOutOutcome { rotate_runtime_key: true, signed_out: true }`, then a
   status with a **new** runtime key, signed out, `grant: false`.

## 7. Clean up

`cli A signout`, `cli B signout`, delete `/tmp/signet-a` and `/tmp/signet-b`. In My
Signet, remove the "Signet CLI" connected app and revoke the contacts grants.
