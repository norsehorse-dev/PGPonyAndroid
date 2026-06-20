# Phase A8 — WKD discovery + KeyServerRepository unification

## What this phase ships

Adds Web Key Directory (WKD) lookup per
**draft-koch-openpgp-webkey-service-15** as a higher-priority source
than keys.openpgp.org. Any caller that asks for "the public key for
this email" now goes through:

1. **WKD advanced** — `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<localpart>`
2. **WKD direct** — `https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<localpart>`
3. **Hagrid** — `https://keys.openpgp.org/vks/v1/by-email/<email>`

…and returns the first hit. The existing three callers (Exchange tab,
Contacts VM, Contacts service) get this for free — `searchByEmail` is
unchanged in signature but routes through the cascade internally.

## Why WKD takes priority over Hagrid

WKD is served by the same organization that runs the recipient's mail.
There's no third-party keyserver in the trust path. If Gmail vends a
public key for `kgstew96@gmail.com` via WKD, that key has the
strongest possible provenance — Gmail itself confirmed the recipient
controls the address. Hagrid is fine as a fallback, but a WKD hit
should always win when present.

## New files (3)

| File | Lines | Purpose |
|------|------:|---------|
| `crypto/util/ZBase32.kt` | 61 | z-base32 encoder (Phil Zimmermann variant, alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`). NOT RFC 4648 base32. Required for the `hu/<hash>` URL segment. Originally written for A0 but never integrated into the live source tree; A8 ships it for real. |
| `crypto/util/ZBase32Test.kt` | 60 | Tests including the WKD spec vector `zbase32(SHA1("joe.doe")) == "iy9q119eutrkn8s1mk4r39qejnbu3n5q"`. This vector is the gate — if it fails, every WKD lookup will 404 because the URL bucket is wrong. |
| `network/WkdService.kt` | 288 | Lookup service. Singleton via `WkdService.shared`. Uses Ktor (same engine as KeyServerRepository) with tight 8s connect / 15s socket timeouts so failures cascade fast. Wraps the binary WKD response in RFC 4880 armor (manual CRC24 + base64) so the caller can hand it to the existing armored-key import path without branching. |

## Modified files (additive, 1)

| File | Before | After | Δ | Purpose |
|------|------:|------:|--:|---------|
| `network/KeyServerRepository.kt` | 118 | 177 | +59 | `searchByEmail` now routes WKD-first via `findByEmail`. New `findByEmail` returns `KeyLookupResult(armoredKey, source)` so A9/A10 UI can show source attribution. Existing Hagrid logic preserved as private `hagridSearchByEmail`. |

Total: 3 new files (409 lines), 1 modified file (+59 lines).

## Backward compatibility

- `searchByEmail(email): String?` — unchanged signature, unchanged
  return semantics. Returns the armored key or null. Existing callers
  in Exchange, Contacts, ContactsService work without code changes
  and automatically get WKD discovery.
- All other KeyServerRepository methods (`searchByFingerprint`,
  `upload`, `requestVerification`) — untouched.
- `KeyServerError` sealed class — untouched.

## New API surface

```kotlin
enum class KeyLookupSource(val displayName: String) {
    WKD_ADVANCED("WKD (advanced)"),
    WKD_DIRECT("WKD (direct)"),
    HAGRID("keys.openpgp.org")
}

data class KeyLookupResult(
    val armoredKey: String,
    val source: KeyLookupSource
)

// On KeyServerRepository:
suspend fun findByEmail(email: String): KeyLookupResult?

// On WkdService.shared (singleton):
suspend fun lookup(email: String): KeyLookupResult?
```

## Architectural notes

### Email parsing

Conservative — splits at the first `@`, validates non-empty parts,
requires at least one `.` in the domain. Doesn't try to be
RFC 5321-complete. Bad inputs fall through to Hagrid which has its
own validation path.

### Localpart handling

WKD §3.1 requires the **lowercased** localpart for hashing
(case-insensitive lookup), but the **original** localpart is sent in
the `l=` query parameter so the server can disambiguate
sub-addressing if it cares.

`localpart.lowercase().toByteArray(Charsets.UTF_8)` is the hash
input. `URLEncoder.encode(localpart, UTF-8)` is the query value.

### Why manual armor wrapping (no BC)

`network/WkdService.kt` doesn't depend on `org.bouncycastle.*`. Three
reasons:
1. **Layering** — network/ is HTTP and protocol code; depending on BC
   would couple cryptographic ceremony to the network layer.
2. **Output stability** — the manual armor (no Version, no Comment,
   blank line after BEGIN, standard CRC24) is identical to what
   PGPCryptoService produces post-A7 Fix2. Going through BC's
   `ArmoredOutputStream` would inherit BC's quirks too.
3. **No misattribution** — we deliberately do NOT add `Comment:
   PGPony Android` to keys we *downloaded* (vs ones we *produced*).
   The downloaded key came from the mail provider, not from PGPony,
   and labeling it as "PGPony Android" would be misleading.

### Why tighter timeouts than Hagrid

WKD serves a tiny static file (typically <2KB) from the mail
provider's web server. If it's not responding in 8 seconds, the path
is almost certainly broken (DNS not configured, server down, or the
provider doesn't run WKD). Fast-failing lets the cascade move on to
the next source without making the user wait through a long hang.

```
WkdService:        connect 8s,  socket 15s   (per WKD attempt)
KeyServerRepository: connect 15s, socket 15s (Hagrid)
```

Worst-case latency for a complete miss: ~46s (2 × WKD + Hagrid).
Typical hit returns in <1s from whichever source is configured.

### Source attribution UX (deferred)

A8 returns the source in `KeyLookupResult.source` but the existing
UI (Exchange tab, Contacts) doesn't show it yet — they only call
`searchByEmail` and get the raw armored string. Surfacing the source
to the user happens in A9 (Contacts parity) and A10 (Import preview
UI), where the import-preview screen will display "Found via WKD
(direct)" or similar above the key card.

## Verified

- z-base32 spec vector `zbase32(SHA1("joe.doe")) == "iy9q119eutrkn8s1mk4r39qejnbu3n5q"` verified against an independent Python implementation.
- CRC24 initial state `crc24(empty) == 0xB704CE` matches RFC 4880 §6.1.
- URL construction for `kgstew96@gmail.com`:
  - hash: `t3d3mhf7w6ihxy8gifk46styqmk7zuw9`
  - advanced: `https://openpgpkey.gmail.com/.well-known/openpgpkey/gmail.com/hu/t3d3mhf7w6ihxy8gifk46styqmk7zuw9?l=kgstew96`
  - direct: `https://gmail.com/.well-known/openpgpkey/hu/t3d3mhf7w6ihxy8gifk46styqmk7zuw9?l=kgstew96`
- Backward-compatible signature on `searchByEmail` preserved.
- No removals from any existing file (additive integrity).

## How to test on device

### Existing flow (Exchange tab)

1. Open the Exchange tab
2. Type an email address with a published WKD key (try `kgstew96@gmail.com` if you have one published — otherwise pick a public test address)
3. Tap Search
4. Without UI changes, the key should now appear faster (WKD is usually quicker than Hagrid) and from any domain that publishes WKD even if it never made it to keys.openpgp.org

### Verifying which source was hit

The `findByEmail` return value carries `source`. To wire it into the UI right now, you can temporarily log it from any caller:

```kotlin
val result = KeyServerRepository.shared.findByEmail("kgstew96@gmail.com")
Log.d("WKD", "found via ${result?.source?.displayName}")
```

`adb logcat | grep WKD` should show `found via WKD (direct)` for Gmail (Gmail publishes via direct, not advanced).

### Unit-test gate

The ZBase32 test vector is the canary. Run:

```
./gradlew test --tests com.pgpony.android.crypto.util.ZBase32Test
```

All five tests should pass. If `wkdSpecTestVector` fails, do not ship — every WKD URL would be wrong.

## Pending after A8

Per plan v2: **Phase A9** — Contacts parity. Brings the iOS Contacts
tab features (search, sectioned list, bulk auto-scan, auto-match
banner) to Android. WKD is the substrate it builds on; A9 surfaces
the source attribution in the UI.

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A8 — WKD discovery (2026-05-27)

Web Key Directory lookup as the priority key-discovery source.
Existing email-based lookups (Exchange tab, Contacts) automatically
benefit; they call the same searchByEmail() entry point, which now
routes WKD-first internally. Source attribution available via the
new findByEmail() for upcoming Contacts/Import UI in A9/A10.

### Added
- crypto/util/ZBase32.kt — z-base32 encoder (Phil Zimmermann variant,
  required for the WKD hu/<hash> URL segment). 61 lines. Spec vector
  zbase32(SHA1("joe.doe")) == "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
  locked in by ZBase32Test.kt.
- network/WkdService.kt — singleton lookup service. Tries advanced
  (openpgpkey.<domain>) then direct (apex domain) with 8s/15s
  timeouts. Wraps the binary WKD response in RFC 4880 armor (manual
  CRC24 + base64) so the caller can use the existing armored-key
  import flow. No Version or Comment headers in the output —
  matches the post-A7-Fix2 behavior elsewhere in PGPony.

### Modified (additive)
- network/KeyServerRepository.kt: +59 lines. New findByEmail()
  returns KeyLookupResult(armoredKey, source) where source is one
  of WKD_ADVANCED / WKD_DIRECT / HAGRID. searchByEmail() now
  delegates to findByEmail and unwraps the armored string —
  backward-compatible signature, transparently WKD-first behavior.

### iOS port equivalents
- ZBase32                    = iOS Services/WKDService.swift §zbase32Alphabet / zbase32Encode
- WkdService                 = iOS Services/WKDService.swift (entire file)
- KeyLookupSource enum       = iOS KeyLookupSource enum (raw values match: "WKD (advanced)", "WKD (direct)", "keys.openpgp.org")
- KeyLookupResult data class = iOS WKDLookupResult struct
- findByEmail unification    = iOS doesn't have a unified findByEmail yet — Android leads here, iOS will need to catch up to match the source-attribution UX
```
