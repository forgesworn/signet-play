# Signet contacts v2 conformance vectors

Byte-for-byte copies of the frozen vectors in `forgesworn/signet-contacts`
`vectors/`, taken at upstream commit
`fbb13cdeefb3e07421228ab3245b7e17e403ecab` (fbb13cd).

| File | Asserted by |
|---|---|
| `pairing.v2.json` | `build_pairing_uri`, `parse_ack`, the §4 tags |
| `pairing-code.json` | `pairing_code`, `format_pairing_code` |
| `envelope.v2.json` | `open_vault_envelope` (`railSecretKey`/`appSecretKey` are TEST KEYS ONLY) |
| `projection.v2.json` | `parse_projection`, incl. every `malformed` and `uncovered` case |
| `sanitise.json` | `sanitize_wire_text` |

Do not edit these files. If upstream regenerates them, copy the new files over
unchanged, update the commit above, and fix the Rust port until the tests in
`../tests.rs` pass again. The upstream contract is `docs/WIRE.md` (v2, frozen).
