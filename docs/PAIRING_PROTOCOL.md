# PGPony pairing protocol v1

Status: v1, 2026-09-30. Byte-exact: every platform builds against this document, and a change to
any byte below bumps the version.

Two PGPony installs on the same network pair for one session and move public keys, key pairs
or a full backup between them. Desktop 3.0.0 is the first release that ships it (two computers).
Android and iOS pick it up in a later update with the same protocol, joining by QR code
(section 8).

Where it lives:

| Platform | Code | Tests |
|---|---|---|
| Android | `app/src/main/java/com/pgpony/android/pair/` (this repo, the source of truth) | `app/src/test/kotlin/com/pgpony/android/pair/` |
| Desktop | the same package, vendored by `tools/sync-vendor.sh` into `vendor/app-pair/` | vendored with the Android tests |
| iOS | `Packages/PGPonyPair/` in the iOS app (Swift, CryptoKit) | `swift test` in that folder |

The test vectors (section 10) live in `app/src/test/resources/pairing/` and are copied, not
regenerated, into the other trees.

Decided (2026-09-30):
- Authentication is numeric comparison: both screens show the same six-digit code and each
  user confirms it matches. No PAKE, so every platform needs only X25519, SHA-256, HMAC and
  AES-GCM (CryptoKit has all four).
- A pairing lasts one session. Its keys are wiped when either side closes; nothing is stored,
  and no listener runs outside an open pairing window.
- The Kotlin code is one package shared by Android and desktop, and it depends on nothing but
  the JDK, Bouncy Castle's X25519 and kotlinx.serialization's JSON elements. Phase 2 is the
  PonyDirect LAN identify handshake, written out in section 4 and copied into the package
  rather than linked, so neither app takes PonyDirect as a dependency.

## 1. Roles and transport

- The **host** opens a pairing window and listens. The **joiner** connects to it. Either can
  be a computer or a phone, and items can move both ways once paired.
- Transport is one TCP connection on the local network. The host listens on an ephemeral port
  on every interface for the length of the window (10 minutes at most), accepts one
  connection, and closes the listener as soon as that connection arrives, so there is never a
  second one to turn away. (ABORT reason 1, busy, is reserved for a host that keeps listening.)
- The host screen shows its address with the port, for example `192.168.1.20:49152`, which a
  joiner can type, and the invite QR code (section 8), which a phone scans. No mDNS: nothing
  is advertised.
- A window ends after one pairing attempt, whatever its outcome. A failed or refused pairing
  needs the user to open a new window, so an attacker gets one guess at the code per window.
  The cost is that anything else that connects first, even by accident, uses up the window.

The connection has three phases:

1. Pairing handshake, framed as below with the magic `PGPP`.
2. Key confirmation, the PonyDirect LAN identify handshake keyed with the pairing key.
3. The session: `ENVELOPE` frames, each carrying one encrypted message.

## 2. Framing

Every frame in every phase has the same shape:

    type(1) | length(4, big-endian) | payload(length)

A frame longer than 1,114,112 bytes (1 MiB plus 64 KiB) is a protocol error. All integers are
big-endian. Labels are ASCII with no terminator. `||` is concatenation.

## 3. Phase 1: pairing handshake

The joiner writes the 4 ASCII bytes `PGPP` on connect; the host checks them and replies with
`PGPP`. Then:

| Type | Name | Direction | Payload |
|---|---|---|---|
| `0x41` | JOIN | joiner to host | `version(1) = 0x01` \|\| `pk_J(32)` |
| `0x42` | ACCEPT | host to joiner | `pk_H(32)` \|\| `commit(32)` |
| `0x43` | NONCE_J | joiner to host | `n_J(32)` |
| `0x44` | NONCE_H | host to joiner | `n_H(32)` |
| `0x4F` | ABORT | either | `reason(1)` |

- `pk_J`, `pk_H`: X25519 public keys (RFC 7748). The joiner's is fresh for each attempt. The
  host's is generated when the window opens, so the invite QR can carry its hash, and dropped
  when the window closes.
- `n_J`, `n_H`: 32 random bytes each, fresh for each attempt.
- `commit = HMAC-SHA256(key = n_H, "pgpony/pair/commit/v1" || pk_H || pk_J)`

The order matters. The host commits to `n_H` before it sees `n_J`, and the joiner sends `n_J`
before it sees `n_H`, so neither side, and no one in the middle, can pick a nonce that steers
the code. On NONCE_H the joiner recomputes `commit` and aborts with reason 3 if it differs.
A joiner that came from an invite also checks `pk_H` on ACCEPT (section 8).

Both sides then compute:

    Z   = X25519(own secret, peer public key); all-zero Z aborts (reason 3)
    T   = SHA-256("pgpony/pair/transcript/v1" || pk_J || pk_H || n_J || n_H)
    PRK = HKDF-Extract(salt = T, ikm = Z)                       (HKDF-SHA256, RFC 5869)
    K    = HKDF-Expand(PRK, "pgpony/pair/key/v1", 32)           pair key, phase 2
    k_HJ = HKDF-Expand(PRK, "pgpony/pair/host-to-joiner/v1", 32)
    k_JH = HKDF-Expand(PRK, "pgpony/pair/joiner-to-host/v1", 32)
    code = uint32(first 4 bytes of SHA-256("pgpony/pair/code/v1" || T)) mod 1,000,000

Each Expand is one HMAC block: `HMAC-SHA256(PRK, label || 0x01)`. The code is shown as six
digits in two groups of three, zero-padded (`042 917`).

ABORT reasons: 1 busy, 2 unsupported version, 3 handshake failed, 4 refused by the user,
5 timed out. The sender closes the connection after an ABORT. Any other frame type in
phase 1 is a protocol error: close without a reply.

Timeouts: 30 seconds for each phase 1 frame; 5 minutes for the users to compare the code.

## 4. Phase 2: key confirmation

Each screen shows the code and asks whether the other device shows the same one.

| Type | Name | Direction | Payload |
|---|---|---|---|
| `0x01` | HELLO | joiner to host | `d(16)` \|\| `HMAC-SHA256(K, "ponydirect/id/v1" \|\| d)` |
| `0x02` | HELLO_ACK | host to joiner | `l(16)` \|\| `HMAC-SHA256(K, "ponydirect/id-ack/v1" \|\| d \|\| l)` |
| `0x03` | NO_MATCH | host to joiner | 48 random bytes |

`d` and `l` are 16 fresh random bytes. This is PonyDirect's LAN identify handshake
(PonyDirect WIRE-PROTOCOL.md) with `K` as its pair key; the table above is all of it.

- When the joiner's user confirms, the joiner writes the 4 ASCII bytes `PDR1` and HELLO. If
  its user says no, it sends ABORT 4 instead.
- The host reads the HELLO but does not answer it until its own user confirms. Then it checks
  the HELLO tag with `K`: if it verifies, the host writes `PDR1` and HELLO_ACK; if not, it
  writes `PDR1` and NO_MATCH and closes. If the host's user says no, it sends ABORT 4 instead
  (a phase 1 frame; the host has not written `PDR1` yet).
- The joiner checks HELLO_ACK with `K`. NO_MATCH or a bad tag ends the attempt.
- A side reads the other's answer as soon as it arrives, so a refusal on one screen closes the
  other screen's question at once instead of waiting for its user.

HELLO and HELLO_ACK prove that each side shares `K` with the connection it is talking to, which
ties the users' decision to this exchange: once the codes matched and both users confirmed, no
one else holds the session keys. Someone in the middle has to run a separate exchange with each
side and ends up with two unrelated codes on the two screens. The chance that they match is one
in a million, and the window closes after that one try. A user who confirms without comparing is
the only way through, which is why both users confirm and the screen says what a mismatch means.

## 5. Phase 3: the session

Every message is one `ENVELOPE` (`0x04`) frame whose payload is:

    seq(8) || AES-256-GCM(key, nonce = 0x00000000 || seq(8), aad = "pgpony/pair/msg/v1" || seq,
                          plaintext = type(1) || body)

`key` is `k_HJ` for messages the host sends and `k_JH` for the joiner's. `seq` starts at 0 in
each direction and goes up by one per message; a receiver requires exactly the next value, so a
replayed, dropped or reordered message ends the session. The ciphertext includes the 16-byte
tag. The plaintext is at most 1,048,576 bytes.

| Type | Name | Body |
|---|---|---|
| `0x01` | INFO | JSON `{"name": "...", "app": "PGPony Desktop 3.0.0", "accepts": [kind, ...]}` |
| `0x10` | OFFER | JSON `{"items": [ITEM, ...]}` |
| `0x11` | ANSWER | JSON `{"accept": [id, ...]}`, empty to decline all |
| `0x20` | ITEM_BEGIN | `id(4)` \|\| `size(8)` |
| `0x21` | ITEM_DATA | `id(4)` \|\| bytes |
| `0x22` | ITEM_END | `id(4)` \|\| `SHA-256 of the item(32)` |
| `0x30` | RESULT | JSON `{"id": n, "ok": true, "error": null}` |
| `0x3F` | BYE | empty |

`ITEM` is `{"id": n, "kind": "public-key" | "key-pair" | "backup", "name": "...",
"fingerprint": "hex or null", "size": n}`. JSON is UTF-8. Member order is not significant and
unknown members are ignored; an unknown message type ends the session.

`accepts` in INFO lists the item kinds that side can import. Left out, it means all three. A
side offers nothing the other does not accept, and a receiver never accepts an item whose kind
it does not know. This lets a platform join before it can restore every kind (a phone that
cannot yet read a PGPony backup file leaves `backup` out).

Flow: each side sends INFO first (device names travel only inside the session, never in the
clear). Either side may then send an OFFER. The receiver shows it, the user picks, and the
receiver answers with the ids it accepts. The sender sends each accepted item as ITEM_BEGIN,
ITEM_DATA messages that each stay within the plaintext limit (at most 1,048,571 item bytes
apiece; a receiver takes any split), and ITEM_END; the receiver checks the size and hash,
imports it, and reports a RESULT for that id. A side may send another OFFER after the RESULTs
for the previous one. BYE, or closing the connection, ends the session; both sides then wipe
`K`, `k_HJ` and `k_JH`.

Limits: one item is at most 64 MiB, one OFFER lists at most 1,000 items, and a side has at most
one OFFER outstanding.

## 6. What moves

- **public-key**: one certificate, armored, as PGPony exports it.
- **key-pair**: one secret key, armored, as PGPony exports it, and never unprotected. A key with
  a passphrase goes as stored, and the receiver needs that passphrase to use it. A key without
  one is exported under a transfer passphrase the sending user types (the stored key is not
  changed). It arrives protected by that passphrase; the receiving user needs it to use the key
  and can change or remove it in Key Detail. A key on a security key or smart card goes as a
  public key only.
- **backup**: a PGPony backup file (the Android and desktop `backup/` format), encrypted under a
  recovery code generated for this transfer. The sending screen shows the code and the
  receiving user types it, as in a restore from a file.

The receiver imports through the same code as a file import or a restore, with every check
those run. Pairing adds a way to carry the bytes and nothing else: no item skips validation,
and nothing is imported that the receiving user did not accept.

## 7. What an observer learns

Someone watching the network sees two addresses, the port, the `PGPP` and `PDR1` magics, two
X25519 public keys, the nonces, and the sizes and timing of the encrypted messages. Device
names, key names, fingerprints and all key material are inside the session. The session key
never leaves memory and is not reused across windows. The invite QR code carries only
addresses and a hash of the host's public key.

## 8. The invite (QR code)

The host shows its invite as a QR code (byte mode; the invite is short, so any error correction
level fits):

    pgpony-pair:1?a=<address>[,<address>...]&h=<base64url(SHA-256(pk_H)[0..16])>

- `a` lists 1 to 8 addresses, the one most likely to work first. An address is an IPv4
  dotted quad (no leading zeros) or an IPv6 literal in brackets (no zone), then `:` and a port
  from 1 to 65535 (no leading zeros). Names are refused, so an invite can never make the
  joiner look something up. IPv6 is written lowercase.
- `h` is the first 16 bytes of SHA-256 of the host's window key, base64url with no padding:
  exactly 22 characters, and the 4 unused bits of the last one are zero (one spelling per
  hash).
- The scheme is matched without regard to ASCII case (no other case folding) and surrounding
  white space is trimmed.
  Members come in any order, separated by `&`; `a` and `h` must each appear exactly once,
  every member must have an `=`, and other members are ignored so a later version can add
  some. No percent-encoding: the characters above are all an invite uses.
- Any other version than `1`, or anything that breaks the rules above, is not an invite: the
  scanner says so and does nothing.

A joiner that scanned an invite connects to the addresses in order (3 seconds each) and uses
the first that answers. On ACCEPT it checks that SHA-256(`pk_H`) starts with `h`, in constant
time; a mismatch aborts with reason 3. The code comparison in phase 2 stays in place, since
the invite authenticates the host to the joiner but not the joiner to the host.

A joiner may also take a typed `address:port` with no invite; then there is no key check
before phase 2, and the code comparison carries it alone.

## 9. Platform notes

**Android.** Every call in the Kotlin package blocks: run it on `Dispatchers.IO`. The app keeps
the screen on while a window is open or a session runs, and ends the pairing when the activity
goes to the background for good (there is no foreground service for this). The `INTERNET`
permission is already declared. Apps that target Android 17 (API 37) also need
`ACCESS_LOCAL_NETWORK`, a runtime permission in the Nearby devices group, for any socket to a
LAN address, host or joiner; ask for it when the user opens the pairing screen
(developer.android.com/privacy-and-security/local-network-permission). The QR code is drawn and
scanned with ZXing, which the app already uses. Platform code supplies what the core leaves
out: the list of what can be offered, the key export with a transfer passphrase, the backup
export, and the import of what arrives, all through the existing keyring and backup services.

**iOS.** The Swift package speaks the same bytes over an async transport; `NWPairTransport` wraps
an `NWConnection` and `NWPairListener` an `NWListener` (Network framework). The first LAN
connection shows the system's local network prompt, so `NSLocalNetworkUsageDescription` must be
in Info.plist, with text that says it is for pairing with another device (no Bonjour services
are declared: nothing is advertised). Scanning the invite needs the camera
(`NSCameraUsageDescription`). A pairing runs in the foreground only: iOS suspends sockets soon
after the app leaves the screen, so leaving ends it. Keep the idle timer off while it runs. The
app lists `backup` in `accepts` only once it restores a PGPony backup file from Android or
desktop.

**Desktop.** Hosts and joins; shows the invite QR on the host screen and accepts a pasted
invite in the join field, where the key check applies as for a scan.

## 10. Test vectors

In `app/src/test/resources/pairing/`, checked by the Kotlin tests and by an independent Python
implementation when they were made. An implementation that does not reproduce them does not
speak this protocol.

- `v1-vectors.json`: one attempt's X25519 keys and nonces, `commit`, `Z`, `T`, `K`, `k_HJ`,
  `k_JH`, `code`, and the first sealed message in each direction.
- `v1-session.json`: every byte of one whole session in both directions (handshake,
  confirmation, INFO, OFFER, ANSWER, one item, RESULT, BYE) with the randomness fixed, plus
  each phase 3 message on its own: sender, `seq`, plaintext, whole frame, and the parsed JSON.
  Replaying the script with the same random bytes must write exactly `host_to_joiner` and
  `joiner_to_host`. An implementation that writes its JSON members in another order matches
  the handshake prefixes and every listed frame (sealing the listed plaintexts), and parses
  every listed body; that is the bar.
- `v1-invites.json`: invites that must parse, with the addresses and hash they carry and the
  canonical form written back, and invites that must be refused, each with the reason.

## 11. Adding a platform

1. X25519, HMAC-SHA256, SHA-256 and AES-256-GCM, with HKDF written out as in section 3.
2. Reproduce `v1-vectors.json`, then the handshake prefixes and every frame of
   `v1-session.json`, then `v1-invites.json`.
3. Pair against desktop both ways (host and joiner), with a mismatched code on each side once,
   and move one item of each kind the platform accepts.
4. Run the flows of section 9 and list the platform's `accepts` honestly.
