# PGPony 4.4.0 planning

Status: planning. Feature list for the 4.4.0 cycle. Android leads, then iOS, then
desktop, per the new-feature procedure (a genuinely new capability is built on Android
first, then ported).

## Post-quantum signatures: composite ML-DSA (RFC 9980)

Requested on the core repo (PGPonyCore #1). PGPony's post-quantum support today covers
only the encryption half of RFC 9980: the composite ML-KEM schemes (ML-KEM-768+X25519 and
ML-KEM-1024+X448, in both the IETF v6 and LibrePGP forms). The signature half, the
composite ML-DSA schemes, is not implemented.

RFC 9980 (Post-Quantum Cryptography in OpenPGP, June 2026), Table 1, composite signatures:

- ID 30: ML-DSA-65+Ed25519 (MUST)
- ID 31: ML-DSA-87+Ed448 (SHOULD)
- IDs 32 to 34: SLH-DSA-SHAKE variants, standalone (MAY)

Scope for 4.4.0: implement at least the MUST, ID 30 (ML-DSA-65+Ed25519). ID 31 (SHOULD) is
a reasonable stretch; the standalone SLH-DSA options (MAY) are out of scope for now.

Work:

- Generation: a v6 key whose signing key uses the composite ML-DSA-65+Ed25519 scheme,
  alongside the existing ML-KEM encryption subkey. Decide whether the composite signer is
  the primary or a dedicated signing subkey (the v6 layout already uses a distinct signing
  subkey).
- Sign and verify: produce and verify composite signatures over both messages and
  certifications.
- Import and display: recognize a key that carries a composite ML-DSA signing key, label
  it, and surface it in the key detail like the ML-KEM composite algorithms are today.
- Interop: verify against GnuPG 2.5.x in both directions, the same bar the ML-KEM composite
  work was held to (round-tripped against 2.5.21).

Research and unknowns (settle before scoping the implementation):

- BouncyCastle ML-DSA (Dilithium) support in the version in use, and whether its OpenPGP
  API exposes the composite signature algorithm IDs, or whether the signature and binding
  packets need the hand-assembly that parts of the ML-KEM composite path already use (see
  CompositeKeyGen and the v5/v6 binding-signature builders).
- The RFC 9980 composite signature packet format: how the ML-DSA and Ed25519 signatures are
  concatenated and encoded, plus the hashing and domain-separation rules.
- Whether the LibrePGP composite variant is wanted too, or IETF v6 only to start.

Delivery:

- Implement in the vendored crypto so it syncs to desktop; iOS is a separate Swift
  port that mirrors the Android implementation once it is verified.
- Not urgent per the reporter. A 4.4.0 target with no committed date.


## Proxy and Tor stream isolation [RC4]

Committed to 4.4.0 RC4, alongside composite passphrase protection and #51. The base
proxy already ships: network/ProxyPrefs.kt (Off / Orbot / Custom with a SOCKS5 host and
port) and network/HttpClientFactory.kt (the Ktor client built from that config, cited as
the cross-app Ktor template). This item is the delta only: an optional SOCKS5 username and
password for Tor stream isolation ("traffic separation"). The full brief is
proxystreamisolationbrief.md at the repo root.

Work:

- ProxyPrefs: add optional username and password (blank by default) for both Orbot and
  Custom, and fold them into the config signature so the shared client rebuilds when they
  change.
- HttpClientFactory: send a nonempty username/password as SOCKS5 user/pass auth; blank
  means no auth. Java does not expose per-client SOCKS credentials cleanly, so this likely
  needs a process-global Authenticator scoped to the proxy host, or a small manual SOCKS5
  handshake. Keep the extended-under-proxy timeouts.
- Settings UI: add the two fields to the existing Proxy section, shown for Orbot and
  Custom. Localize the new strings, English default at minimum.
- Coverage: route every outbound path through the single shared client (API, key and
  directory lookups, WKD, keyserver, update checks, background workers). One missed path is
  a leak.

Notes and requirements:

- Fail-closed on every path: an enabled but unreachable proxy fails the request and never
  falls back silently to a direct connection. Ktor's SOCKS engine already throws; do not
  add a direct-retry.
- No DNS leak: the target hostname resolves at the proxy, not on device.
- Off by default, so no existing user's connectivity changes on update.
- No change to the crypto core or any wire format.

Delivery:

- Verify on-device with Tor that distinct username/password pairs land on distinct circuits
  (IsolateSOCKSAuth), and that killing the proxy fails requests instead of going direct.
- iOS is out of scope here: URLSession does not support SOCKS5, which the brief flags for a
  separate human decision rather than a fake field.


## E-mail key selection on the send path (#51) [RC4]

Requested by RandomNam3 (FairEmail). When PGPony is invoked to encrypt or sign an
outgoing email, the first key chosen for that account is remembered and the choice
is never offered again, so a second key on the same address is unreachable.

Work:

- On the compose/send entry path, surface the key as a selector rather than a
  one-time cached pick: offer "remember for this account" with a visible change
  control, or "ask every time", defaulting to a way to switch.
- Find where the per-account key is cached (the ACTION_SEND / mailto / share
  handling) and add a change affordance instead of the silent lock-in.
- Keep the one-tap flow for the common single-key case; the selector only needs
  to appear when the account has more than one usable key, or behind a small
  "change key" control.

Delivery: Android first, verified with FairEmail using an account that has two
keys on the same address.
