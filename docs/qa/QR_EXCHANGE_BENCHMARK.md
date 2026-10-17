# QR exchange evidence and physical benchmark record

Recorded on 2026-10-17. The source reference is 4.7.0 RC6,
`f04501acd56f74da190789bd32c2ceed90a75e8c`. This record separates deterministic encoding
and synthetic luminance results from measurements requiring physical phones.
**Phone-to-phone performance and release acceptance remain untested.**

## Public dataset and ownership

Only the four explicitly selected public certificates are packaged in the instrumentation
APK. No directory containing secret keys was copied. The canonical manifest is
[`app/src/androidTest/assets/qr/manifest.json`](../../app/src/androidTest/assets/qr/manifest.json).
It pins each source path, certificate type, complete SHA-256, armor byte and character
length, and decoded binary length. All four armor files are ASCII, so their character and
byte lengths coincide. Binary lengths exclude armor and its CRC line.

| Fixture | Source under `app/src/test/resources` | Armor characters | Binary bytes |
| --- | --- | ---: | ---: |
| RFC 9580 version 6 | `rfc9580/a3_cert.asc` | 650 | 424 |
| RSA | `keys/uid-selfsig-expiry-rsa.asc` | 2,468 | 1,762 |
| Ed25519 / ML-KEM-768 | `pqc/rfc9980-a2-v4-ed25519-mlkem768-pub.asc` | 2,348 | 1,680 |
| ML-DSA-65 / Ed25519 | `pqc/rfc9980-a3-mldsa65-ed25519-cert.asc` | 18,554 | 13,647 |

Capacity inputs are generated as 32,000 and 32,001 ASCII `A` characters. They test the
transport ceiling; neither is represented as a public certificate or an import test.
Every profile accepts the former in 32 parts and rejects the latter.

## Actual production encoding results

The probe calls production `QrChunking.split(text, policy)` and
`QrSymbolLayout.forFrames(frames, policy)` with complete frame headers. It includes the
canonical boundary rule, frame-count clamping, raw threshold, shared version, UTF-8
encoding and four-module quiet zone. Symbols below 1,201 characters retain the original
unframed text. Their chosen profile still controls QR error correction.

| Fixture | Profile | Frames | Shared QR version | QR modules without quiet zone | Full matrix modules |
| --- | --- | ---: | ---: | ---: | ---: |
| RFC 9580 version 6 | 1,000 / L | 1 | 18 | 89 | 97 |
| RFC 9580 version 6 | 750 / M | 1 | 20 | 97 | 105 |
| RFC 9580 version 6 | 600 / M | 1 | 20 | 97 | 105 |
| RSA | 1,000 / L | 3 | 23 | 109 | 117 |
| RSA | 750 / M | 4 | 20 | 97 | 105 |
| RSA | 600 / M | 5 | 18 | 89 | 97 |
| Ed25519 / ML-KEM-768 | 1,000 / L | 3 | 23 | 109 | 117 |
| Ed25519 / ML-KEM-768 | 750 / M | 4 | 19 | 93 | 101 |
| Ed25519 / ML-KEM-768 | 600 / M | 4 | 19 | 93 | 101 |
| ML-DSA-65 / Ed25519 | 1,000 / L | 19 | 23 | 109 | 117 |
| ML-DSA-65 / Ed25519 | 750 / M | 25 | 22 | 105 | 113 |
| ML-DSA-65 / Ed25519 | 600 / M | 31 | 19 | 93 | 101 |

The machine-readable report is [`qr-encoding.csv`](qr-encoding.csv). Its sequence hash is
SHA-256 over each frame's UTF-8 bytes in sequence order, prefixed by its decimal byte
length and `:`. This makes changes to headers and partition boundaries reviewable.
The ML-KEM fixture demonstrates the same-count rule: 750/M and 600/M both produce four
parts and identical frame bytes. The 650-character certificate stays unframed.

The CSV also reproduces RC6 encoding geometry: its default frame text, ZXing 3.5.3,
default L correction, one-module margin and individually selected versions. RC6 version
ranges were 18–18, 15–23, 13–23 and 16–23 for the four fixtures in table order. This is
an executable reconstruction of encoder geometry; it is **not an unmodified RC6 app
execution, RC6 camera benchmark or timing baseline**. The independent released-format
collector test accepts current default and optional profile frame text.

These sizes describe capacity and display geometry. They do not select a preferred
profile or establish that a smaller matrix completes faster on a phone. The default
remains the released 1,000/L profile and 500 ms cadence.

## Synthetic luminance replay evidence

Twelve deterministic raw `.y` planes are packaged beside the certificates. Every case
uses the first BASELINE frame, a production matrix with a complete quiet zone, explicit
plane offset, padded row stride, pixel stride, full-image crop, rotation and an identity
preview transform. The manifest contains all geometry, file hashes, blur radius and
recorded first-attempt outcome. These are generated images, not sensor captures.

| Synthetic case | Inputs | First-attempt results from production decoder |
| --- | --- | --- |
| Clean, 4 pixels/module | All four public fixtures; pixel stride 1; rotation 0° | 4 decoded correctly |
| Integer box blur, radius 1, 4 pixels/module | All four public fixtures; pixel stride 1; rotation 0° | 4 decoded correctly |
| Clean, 3 pixels/module, padded interleaved plane | All four fixtures; pixel stride 2; rotation 90° | 3 decoded correctly; dense ML-DSA first frame missed |

The miss is retained in the manifest and regression tests. A fixed clock holds fallback
out of the initial attempt, so this records the initial normal search result; heavy retries, full multipart completion and camera reliability were not
measured by this replay. A regression test confirms a decoded result equals the expected
frame; an observed miss is never counted as a successful decode. The separate scanner
unit tests exercise bounded fallback and progress timing with deterministic clocks.

No real camera luminance frames have been collected. Real frame comparisons remain
pending and must retain the same geometry metadata with an explicit capture origin.

## Reproduction and current verification

Use JDK 17, the project Gradle 8.14.3 distribution and ZXing core 3.5.3. On this run the
standalone compiler was Kotlin 2.0.21 from the Gradle distribution. The standalone tool
pins ZXing's Maven Central SHA-256 and requires no Android SDK or network downloads.
See [`tools/qr/README.md`](../../tools/qr/README.md) for cache discovery and path overrides.

```sh
python3 tools/qr/run_core_tests.py
python3 tools/qr/run_core_tests.py --verify-assets --output /tmp/pgpony-qr-reproduced
```

The Android build can run the same probe and verify packaged asset ownership separately:

```sh
./gradlew :app:testFossDebugUnitTest --tests 'com.pgpony.android.qr.QrEncodingProbeTest'
./gradlew :app:connectedFossDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.pgpony.android.qr.QrDecoderReplayTest
./gradlew :app:connectedFossDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.pgpony.android.qr.QrBitmapRenderingTest
```

The standalone harness passed **35 tests** across six classes on 2026-10-17. The production probe
generated the 12 profile rows and 12 synthetic luminance cases. Artifact reproduction also passed: all **16 public asset files**, parsed manifest
metadata and the complete production CSV matched the regenerated output.
Android instrumentation requires a connected device or emulator; emulator results may
verify Android bitmap behavior but must be recorded separately from physical camera data.

## Physical benchmark protocol and results still required

Use a distinct local session ID and a monotonic clock. Record camera binding separately.
Define `t_first` from analysis readiness to first distinct part, `t_complete` to complete
collection or reconstruction, and `t_preview` to the import preview. User confirmation and
actual key import are outside `t_complete`. Collect frame/decode counts, distinct versus
duplicate parts, per-attempt decoder durations, configured analysis resolution and memory
samples. Production metrics hooks default to no operation and must never retain user QR
text, key identifiers or camera images. Public fixtures may be recorded by the QA harness.

| Required run | Physical devices and directions | Result |
| --- | --- | --- |
| RC6 → RC6 on affected phones | Both directions, same fixture and conditions | UNTESTED — affected phones unavailable |
| Current → current on affected phones | Both directions; compare medians, p95 and timeouts with RC6 | UNTESTED |
| RC6 / 4.6.4 → current | Both fixture sizes and raw single QR | UNTESTED |
| Current compatible → RC6 / 4.6.4 | Both fixture sizes and raw single QR | UNTESTED |
| Current enhanced → current | Drop/reorder tolerance plus actual elapsed completion time | UNTESTED |
| Medium/low performance Android ↔ newer Android | At least two physical models; both directions | UNTESTED |
| Memory, decoder allocation and 20 camera reopen cycles | Release build, same phones and fixture | UNTESTED |
| iOS interoperability | Matching implementations, physical devices, both directions | UNTESTED |

Record model, OS, refresh rate, camera resolution, APK commit/hash, sender profile,
frame count, playback cadence, distance, ambient lighting and screen brightness. Begin
with ordinary lighting and 20–30 cm distance. Keep darker, oblique and reflective stress
cases separate. Parameter selection compares profiles and 500/750/1,000 ms intervals
in stages. Preserve all failures and timeouts in the dataset.

The plan's acceptance targets remain unverified: affected-device median completion time
at least 30% lower; at least 38 of 40 core attempts within the stated budget; no material
regression on previously stable combinations; and bounded release-build memory. Encoding
sizes, unit tests and emulator checks do not establish those outcomes. No camera speed or
reliability improvement is claimed by this record.
