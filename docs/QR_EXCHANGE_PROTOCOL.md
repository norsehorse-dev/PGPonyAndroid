# PGPony QR public-certificate exchange

Protocol revision: PGPONY2, 2026-10-17.

This document specifies the experimental enhanced public-certificate transport byte for byte.
Android only offers compatible sending (raw armor or PGPONY1). PGPONY2 receiving and the
reference encoder remain available for interoperability testing; the app has no enhanced
sending option. Sending must remain deferred until the iOS and desktop clients can read
this revision. There is no negotiation or return channel, and Android receiver support
does not establish support in other clients. These changes target a release after 4.7.0.

A receiver recognizes raw armored public certificates, legacy `PGPONY1` multipart text,
and this separate `PGPONY2` prefix. An unknown PGPony transport version must be reported
as unsupported before invoking an armored-key importer. Received certificates enter the
normal import preview and fingerprint verification flow.

## 1. Certificate bytes and bounds

The payload is exactly one complete binary OpenPGP public certificate, obtained by
Bouncy Castle armor decoding when the sender receives armor. Transport must preserve
all original binary packet octets, including identities, attributes, signatures,
revocations and public subkeys. It must not export `PGPPublicKeyRing.encoded` or a
sanitized certificate in place of those octets. Armor headers, line endings and armor
CRC are not part of the binary certificate.

| Quantity | Value |
| --- | --- |
| Certificate length `L` | 1 through 65,536 bytes inclusive |
| Shard width `S` | Exactly 512 bytes |
| Data shards `k` | `ceil(L / 512)`, from 1 through 128 |
| Parity shards `r` | `ceil(k / 4)`, from 1 through 32 |
| Total shards `n` | `k + r`, at most 160 |
| Index | Zero through `n - 1` inclusive |
| Base45 text per shard | Exactly 768 characters |
| Maximum complete frame length | 867 ASCII characters |
| Sender input armor limit | 100,000 characters, before decoding |

There is no compression. Append zero bytes until the payload length is `k * 512`, then
split into `k` consecutive data shards. The final data shard always has 512 bytes, even
for a certificate of one byte. A receiver must check that all reconstructed bytes after
`L` are zero, then discard that padding. SHA-256 covers the first `L` bytes only.

Android validates packet envelopes before transport and after recovery. A certificate
must start with a public primary key (tag 6), contain exactly one primary key, and contain
only public-certificate packet tags 2, 6, 10, 12, 13, 14, 17 and 21. Secret key and secret
subkey packets (tags 5 and 7) are forbidden anywhere. Old and new definite packet-length
headers are accepted. Partial or indeterminate packet lengths are rejected. Claimed
packet lengths must fit entirely within the bounded input before a body is copied.
This restriction can reject otherwise legal unusual packet encodings; it never rewrites
or drops their contents.

Bouncy Castle 1.85 parses ordinary packets and ordinary complete rings. The app also
supports RFC 9980 composite packets that BC cannot parse, and LibrePGP version 5
algorithm-8 material that BC treats as opaque. For these packets the transport checks
the following exact structural shapes and preserves their original bytes:

- Public key algorithms 30 and 31: version 6 only, with a four-byte material length of
  1,984 and 2,649 bytes respectively, and no extra bytes after that material.
- Public key algorithms 35 and 36: version 6, with material lengths 1,216 and 1,624 bytes
  respectively. Algorithm 35 additionally accepts the existing version 4 form, with
  1,216 bytes directly after its six-byte key header.
- LibrePGP algorithm 8: version 5 only. A four-byte public-material length must equal
  the complete remaining packet body. Material is one OID-length byte, the exact curve
  OID, one canonical unsigned point MPI (two-byte big-endian bit count and the minimal
  nonzero point octets), a four-byte Kyber public-key length, and exactly those Kyber
  bytes. No trailing bytes are allowed. The following four suites are supported:

  | Curve | OID body in hex | Point bytes | Kyber public bytes |
  | --- | --- | --- | --- |
  | X25519 | `2B656E` | At most 32, or legacy 33 | 1,184 |
  | X448 | `2B656F` | At most 56, or legacy 57 | 1,568 |
  | brainpoolP256r1 | `2B2403030208010107` | Exactly 65 | 1,184 |
  | brainpoolP384r1 | `2B240303020801010B` | Exactly 97 | 1,568 |

  Native points may use fewer octets because the app restores leading zero bytes when
  interpreting the MPI. Their historical extra-octet form must start with `0x40`.
  Brainpool points must start with the uncompressed-point byte `0x04`. Every MPI bit
  count must agree with its first nonzero octet, including the legacy form. The OID
  fixes the Kyber length; selecting another length with the same OID is invalid.
  The transport preserves both native point representations byte for byte. This
  compatibility does not repair the historical form's separate GnuPG encryption issue.
- Signature algorithms 30 and 31: version 6 only. Hashed and unhashed areas have four-byte
  lengths bounded by the packet. They are followed by two digest-prefix bytes, one salt
  length byte, the salt, and an exact 3,373-byte or 4,741-byte signature respectively.
  Hash algorithms 8/12 require 16 salt bytes, 9 requires 24, 10/14 require 32, and 11
  requires 28. Other hash algorithms are rejected in these composite signatures.

These are structural checks. The transport does not validate certificate self-signatures,
bindings, expiry, revocations or ownership. The existing importer performs its normal
certificate checks and presents the fingerprint to the user.

## 2. Text frame grammar

Every frame is an ASCII string in the QR alphanumeric alphabet:

```text
PGPONY2:<D>:<L>:<k>:<r>:<i>:<C>:<B>
```

`D` is the full SHA-256 digest of the unpadded certificate, encoded as exactly 64 uppercase
hexadecimal characters (`0`–`9`, `A`–`F`). `L`, `k`, `r` and `i` use canonical unsigned
base-10 notation: no sign, whitespace or leading zero, except the integer zero itself
for index zero. `k` and `r` must match the equations above; redundant counts do not
permit alternate shard layouts. `C` is exactly eight uppercase hexadecimal characters.
`B` is RFC 9285 Base45 encoding of the raw 512-byte shard.

**Only the first seven colons delimit fields.** The entire remaining suffix is `B`.
Base45 includes the colon character and the space character. Do not split every colon,
trim whitespace, normalize case, add line breaks or interpret a trailing space as
formatting. A space at the end of a Base45 payload is meaningful data.

The complete frame alphabet is:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:
```

All frames can therefore use QR alphanumeric mode, including their headers. The shard
code below is separate from a QR symbol's internal error correction. QR error correction
can repair errors inside one symbol; transport erasure coding recovers missing symbols.

## 3. Base45

Use the alphabet shown above, with indexes zero through 44, in that exact order. For each
pair of bytes `a, b`, compute `v = 256*a + b`. Emit alphabet characters for `v % 45`,
`floor(v / 45) % 45`, and `floor(v / 2025)`, in that order. For a final unpaired byte,
emit only the first two characters. A triple decoding above 65,535 or a pair decoding
above 255 is invalid. Lengths congruent to one modulo three and characters outside the
alphabet are invalid. There are no aliases and no alternate normalization rules.

RFC 9285 examples:

| Input ASCII bytes | Base45 |
| --- | --- |
| `AB` | `BB8` |
| `Hello!!` | `%69 VD92EX0` |
| `base-45` | `UJCLQE7W581` |

Because shards have even length 512, all frame payloads have exactly 768 characters.

## 4. Shard checksum

`C` is CRC-32/ISO-HDLC, the algorithm implemented by Java `java.util.zip.CRC32` and
Python `binascii.crc32`: polynomial `0x04C11DB7` (reflected `0xEDB88320`), initial register
`0xFFFFFFFF`, reflected input/output and final XOR `0xFFFFFFFF`. Its check value for
ASCII `123456789` is `0xCBF43926`.

Checksum the following concatenation, in order:

1. ASCII encoding of the canonical header `PGPONY2:<D>:<L>:<k>:<r>:<i>:` including its
   final colon, excluding both `C` and the colon following `C`.
2. The raw 512 bytes of the shard, excluding Base45 text.

Format the resulting unsigned 32-bit value as eight uppercase hexadecimal characters.
This binds the digest, length, counts and index to the shard's bytes. A parser must check
all canonical forms, limits and checksum before inserting a shard or replacing a session.

CRC and SHA-256 detect accidental corruption. An attacker can create new checksums and
digests for a different certificate. Neither mechanism authenticates the key owner.

## 5. Exact erasure code

The code is systematic Reed–Solomon over the field GF(256). The field's irreducible
polynomial is `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`). A byte's bits represent polynomial
coefficients; addition is bitwise XOR. Multiplication is polynomial multiplication
modulo `0x11D`. The primitive generator used by the implementation's logarithm table is
integer byte 2. The multiplicative identity is integer byte 1, including `0^0 = 1`
when defining the Vandermonde matrix.

For `n = k + r`, define the `n` by `k` matrix `V` as:

```text
V[row, column] = row^column in GF(256)
row = 0..n-1, column = 0..k-1
```

The row evaluation points are the integer field elements `0, 1, 2, ...`, **not** successive
powers of 2. Let `A` be the first `k` rows of `V`. Compute the generator matrix:

```text
G = V * inverse(A)
```

Matrix operations use the field above. The first `k` rows of `G` are the identity matrix.
For byte position `j` from zero through 511, form each output shard:

```text
shard[row][j] = XOR over c=0..k-1 of GF_multiply(G[row,c], data[c][j])
```

Indexes `0..k-1` are unchanged systematic data shards. Indexes `k..n-1` are parity shards.
The independent Python reference computes the same rows using Lagrange interpolation
at points `0..k-1`, without importing the application or its field tables/matrix code.

Any `k` distinct valid indexes determine the certificate. For selected indexes `I`,
take the corresponding `k` rows of `G` as matrix `H` and solve `data = inverse(H) *
selected_shards`, independently at every byte position. Distinct evaluation points make
`H` invertible. Fewer than `k` shards provide no completion guarantee. This protocol does
not correct an undetected corrupt shard by searching alternative subsets.

## 6. Collector behavior and resource ownership

A receiver maintains one active tuple `(D, L, k, r)` and at most `k` distinct 512-byte
shards. It validates the incoming frame before changing active state. A malformed frame
is ignored with an error result; existing valid progress remains available.

A valid frame with a different tuple discards prior shards, starts a new session and
reports the restart. Identical duplicates do not increase progress. While collecting, a second shard with
the same tuple and index but different bytes is a conflicting duplicate: discard the
session and report malformed input. No shard from one tuple may help recover another.

On the `k`th distinct valid shard, recover data, enforce zero padding, verify the full
digest and validate the recovered public certificate. Failure discards the session and
reports malformed input. Success returns the complete armored certificate for the existing
import preview, clears stored shards and retains the completed metadata and armored result.
Every subsequent valid frame of that same tuple returns the cached completion again after
normal frame parsing and CRC checks. This permits a retry when a lifecycle pause discarded
an asynchronous completion before UI delivery. The scanner session's completion gate owns
exactly-once UI delivery. An explicit reset or a different valid tuple clears the cached
result and begins a fresh session.

The Kotlin collector is not thread-safe. Callers must serialize `offer` and `reset`,
with safe publication if successive calls run on different worker threads. It owns
decoded shard arrays and does not retain incoming strings. Persistent
shard storage is at most 65,536 bytes plus container/metadata overhead. A completed
session retains at most 100,000 characters of armored certificate instead of its shards;
there is only one such cached result. Recovery allocates
bounded matrices and arrays proportional to the fixed limits; it cannot create an
unbounded set of sessions or shards. Rendering must use its own bounded bitmap cache;
the protocol's maximum frame count is not permission to retain 160 full-size bitmaps.

## 7. Independent interoperability artifacts and provenance

The erasure implementation is small project-authored Kotlin source in
`app/src/main/java/com/pgpony/android/qr/v2/ErasureCode.kt`. It introduces no dependency
and copies no third-party implementation. The exact field and matrix specification above
is the interoperability contract. No external audit or third-party implementation
endorsement is implied. ZXing's QR Reed–Solomon classes are not used for shard recovery.

Run the independent Python standard-library reference from the repository root:

```sh
python3 tools/qr/reference_vectors.py
```

It recomputes and compares both checked-in artifacts. `--write` deliberately regenerates
them after a reviewed protocol change. The reference uses bitwise polynomial
multiplication and Lagrange interpolation, independently of Kotlin's logarithm tables
and Gaussian elimination.

| Artifact | SHA-256 |
| --- | --- |
| `tools/qr/reference_vectors.py` | `e40f8f0d51f45930bf9b541b3086453f279b7ffa42d06ad64f1f1b98c6abf3bd` |
| `app/src/test/resources/qr/v2/erasure-vectors.txt` | `b128d0c1d513babbad90a695a731a73d21dfa13b5c40ee04231629abec593739` |
| `app/src/test/resources/qr/v2/certificate-frames.txt` | `eca7dc05afc613a436e7f5bc491a5d0c392256a72f6deefa2e76b5d04ffd164a` |

The erasure artifact uses one line per vector: decimal `k`, decimal `r`, comma-separated
hex data shards, and comma-separated hex complete output shards, separated by `|`.
It includes `(k,r)` pairs `(1,1)`, `(2,1)`, `(4,2)`, `(20,4)` and `(128,32)`.
The `(20,4)` vector tests generic code interoperability; transport senders still derive
`r = ceil(k/4)` and therefore use `(20,5)` for a 20-data-shard certificate.

The frame artifact contains all complete frames, one ASCII line per index, for the
existing public fixture `pqc/rfc9980-a3-mldsa65-ed25519-cert.asc`. The reference dearmors
it independently using Python Base64, computes its SHA-256, padding, parity, CRC and
Base45, and checks every character of every frame against Kotlin output in unit tests.

Automated tests include RFC Base45 vectors, canonical field rejection, payload colons,
checksum coverage, duplicate/conflict/restart behavior, secret packet rejection, malformed
known composite lengths, all four LibrePGP OID/MPI/Kyber structures, full certificate-byte preservation, all 10,626 four-erasure
patterns of RS(24,20), exhaustive small-code patterns and randomized maximum-size recovery.
These deterministic checks establish implementation behavior. Physical camera throughput,
low-light completion and interoperability with another independently implemented client
require separate measurements before such claims are made.
