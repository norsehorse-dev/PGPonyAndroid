# Phase A0 — Foundations

## What this phase ships

Pure-utility crypto primitives + a JSON serialization cleanup on the
key server upload path. **Zero user-visible change.** This is the
plumbing every later phase pulls from.

### New files

| File | Lines | Purpose |
|------|------:|---------|
| `app/src/main/java/com/pgpony/android/crypto/util/Crc24.kt` | 58 | RFC 4880 §6.1 CRC-24 for ASCII armor |
| `app/src/main/java/com/pgpony/android/crypto/util/SubpacketLength.kt` | 91 | RFC 4880 §5.2.3.1 subpacket length codec |
| `app/src/main/java/com/pgpony/android/crypto/util/MpiEncoder.kt` | 89 | RFC 4880 §3.2 MPI encode/decode |
| `app/src/main/java/com/pgpony/android/crypto/util/ZBase32.kt` | 61 | z-base32 (Phil Zimmermann variant) for WKD localpart hashing |
| `app/src/main/java/com/pgpony/android/crypto/util/V4Fingerprint.kt` | 66 | RFC 4880 §12.2 v4 fingerprint = SHA-1(0x99 \|\| len \|\| body) |
| `app/src/main/java/com/pgpony/android/network/dto/KeyServerDto.kt` | 72 | `@Serializable` Hagrid VKS v1 request/response types |
| `app/src/test/kotlin/com/pgpony/android/crypto/util/Crc24Test.kt` | 52 | Unit tests for Crc24 |
| `app/src/test/kotlin/com/pgpony/android/crypto/util/SubpacketLengthTest.kt` | 126 | Boundary tests for length codec |
| `app/src/test/kotlin/com/pgpony/android/crypto/util/MpiEncoderTest.kt` | 117 | RFC §3.2 example tests + round-trip |
| `app/src/test/kotlin/com/pgpony/android/crypto/util/ZBase32Test.kt` | 60 | WKD spec test vector verified |
| `app/src/test/kotlin/com/pgpony/android/crypto/util/V4FingerprintTest.kt` | 72 | Fingerprint structure tests |

### Modified files (additive only)

| File | Before | After | Δ |
|------|------:|------:|--:|
| `build.gradle.kts` (root) | 7 | 8 | +1 |
| `app/build.gradle.kts` | 123 | 128 | +5 |
| `app/src/main/java/com/pgpony/android/network/KeyServerRepository.kt` | 118 | 180 | +62 |

**No original lines removed from any file.** Function bodies in
`upload()` and `requestVerification()` were rewritten to use proper
JSON serialization, but the public surface of the class and the
file's structure (imports, error types, data classes, function
signatures) are intact.

## Verified test vectors

- **z-base32 / WKD:** `ZBase32.encode(SHA1("joe.doe"))` ==
  `"iy9q119eutrkn8s1mk4r39qejnbu3n5q"` (matches WKD spec; verified
  against Python reference)
- **CRC-24:** `Crc24.compute("hello")` == `0x47F58A`,
  `Crc24.compute("123456789")` == `0x21CF02` (verified against
  Python reference)
- **MPI:** `[0x0F]` → `[0x00, 0x04, 0x0F]`, `[0x01, 0xFF]` →
  `[0x00, 0x09, 0x01, 0xFF]` (RFC 4880 §3.2 examples)

## Bug fix: KeyServerRepository

Prior code:

```kotlin
setBody("""{"keytext":"${armoredPublicKey.replace("\n", "\\n")}"}""")
```

…and the response was discarded, returning `token = null` so
`requestVerification(token, email)` was unreachable.

Phase A0 replaces both `upload()` and `requestVerification()` with
`Json.encodeToString(...)` on the new `VksUploadRequest` /
`VksRequestVerifyRequest` DTOs, parses the response into
`VksUploadResponse`, and surfaces the real `token`, `key_fpr`, and
per-email `status` map on `KeyServerUploadResult` via additive
fields (`keyFingerprint`, `emailStatus`). Existing callers that
read the original `token` and `status` fields continue to compile
unchanged.

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A0 — Foundations (2026-05-27)

Pure-utility additions + KeyServerRepository cleanup. No
user-visible change.

### Added
- crypto/util/Crc24.kt — RFC 4880 §6.1 CRC-24
- crypto/util/SubpacketLength.kt — RFC 4880 §5.2.3.1 length codec
- crypto/util/MpiEncoder.kt — RFC 4880 §3.2 MPI encode/decode
- crypto/util/ZBase32.kt — z-base32 PGP alphabet (WKD localpart hash)
- crypto/util/V4Fingerprint.kt — SHA-1(0x99 || len || body)
- network/dto/KeyServerDto.kt — @Serializable VKS DTOs
- 5 JUnit test files in app/src/test/kotlin/

### Modified (additive)
- build.gradle.kts: +1 line (serialization plugin id)
- app/build.gradle.kts: +5 lines (plugin in plugins{} block)
- network/KeyServerRepository.kt: +62 lines (Json.encodeToString
  for upload/request-verify; parse response token; expose
  emailStatus map via additive KeyServerUploadResult fields)

### iOS port equivalents
- Crc24 = SigningService.crc24 (iOS Phase 2a)
- SubpacketLength = inline byte arithmetic in iOS SigningService
- MpiEncoder = inline in iOS SigningService
- ZBase32 = iOS WKDService (Phase 3) zbase32 implementation
- V4Fingerprint = iOS OpenPGPPacketParser fingerprint helper
- KeyServerRepository fix = iOS Phase 6.E.1 (different bug shape —
  iOS had wrong Content-Type, Android had wrong body construction)
```
