# PGPony pairing protocol v1

Status: v1, 2026-10-01. Byte-exact: every platform builds against this document, and a change to
any byte below bumps the version. (v1 has not shipped yet; the 2026-10-01 revision changed `T`,
section 3, and regenerated every vector before any release spoke it.)

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
- Authentication is a six-digit code both sides derive: the joiner's user confirms the two
  screens show the same code, and the host's user types the code the joiner shows (section 4).
  No PAKE, so every platform needs only X25519, SHA-256, HMAC and AES-GCM (CryptoKit has all
  four).
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
- Before it reads a byte, the host checks where the connection comes from. It runs phase 1 only
  for a source address that is loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16,
  fe80::/10), private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), unique local (fc00::/7), or
  inside the subnet of one of the addresses the host lists (its address with that interface's
  prefix length). An IPv4-mapped IPv6 source (`::ffff:a.b.c.d`) is judged as its IPv4 address.
  Any other connection is closed at once, and it does not use up the window: the host keeps
  listening. So a VPN or overlay peer, a public IPv4 or a global IPv6 address elsewhere cannot
  take the window. `v1-peers.json` (section 10) pins the rule. A phone host also keeps its
  listener off cellular interfaces.
- The host screen shows its address with the port, for example `192.168.1.20:49152`, which a
  joiner can type, and the invite QR code (section 8), which a phone scans. No mDNS: nothing
  is advertised.
- A window ends after one pairing attempt, whatever its outcome. A failed or refused pairing
  needs the user to open a new window, so an attacker gets one guess at the code per window.
  The cost is that anything else on the local network that connects first, even by accident,
  uses up the window. The host screen therefore shows the connecting address as soon as a
  connection arrives (section 4).

The connection has three phases:

1. Pairing handshake, framed as below with the magic `PGPP`.
2. Key confirmation, the PonyDirect LAN identify handshake keyed with the pairing key.
3. The session: `ENVELOPE` frames, each carrying one encrypted message.

## 2. Framing

Every frame in every phase has the same shape:

    type(1) | length(4, big-endian) | payload(length)

A frame longer than 1,114,112 bytes (1 MiB plus 64 KiB) is a protocol error. Where the expected
frame has a known size (every phase 1 and phase 2 frame), a declared length above that size is a
protocol error before anything is read or allocated for it. All integers are big-endian. Labels
are ASCII with no terminator. `||` is concatenation.

Every timeout below is a wall-clock limit on a whole frame (from its first byte being awaited to
its last byte), not a limit on each read: a peer that sends one byte at a time cannot hold a
frame open past it. When it passes, the reader closes the connection.

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
    T   = SHA-256("pgpony/pair/transcript/v1" || "PGPP" || version || pk_J || pk_H || n_J || n_H)
    PRK = HKDF-Extract(salt = T, ikm = Z)                       (HKDF-SHA256, RFC 5869)
    K    = HKDF-Expand(PRK, "pgpony/pair/key/v1", 32)           pair key, phase 2
    k_HJ = HKDF-Expand(PRK, "pgpony/pair/host-to-joiner/v1", 32)
    k_JH = HKDF-Expand(PRK, "pgpony/pair/joiner-to-host/v1", 32)
    code = uint32(first 4 bytes of SHA-256("pgpony/pair/code/v1" || T)) mod 1,000,000

`version` is the one byte the joiner sent in JOIN and the host accepted (`0x01`), and `"PGPP"`
is the 4-byte magic, so `T`, the keys and the code all depend on the version both sides ran.
Each Expand is one HMAC block: `HMAC-SHA256(PRK, label || 0x01)`. The code is shown as six
digits in two groups of three, zero-padded (`042 917`).

ABORT reasons: 1 busy, 2 unsupported version, 3 handshake failed, 4 refused by the user,
5 timed out. The sender closes the connection after an ABORT. Any other frame type in
phase 1 is a protocol error: close without a reply.

Phase 1 ABORT frames are not authenticated. An implementation never falls back to an older
version because of ABORT 2 or a closed connection: a retry with another version needs a new
window that the user opens. (Since `T` covers the version, two sides that ran different versions
never show the same code anyway.)

Timeouts: 30 seconds for each phase 1 frame; 5 minutes for the users to compare the code (the
whole phase 2 frame from the other side must arrive within it); in phase 3, 5 minutes for each
frame, so a session with nothing to say for 5 minutes ends.

## 4. Phase 2: key confirmation

The users check the code differently on the two sides:

- The **joiner** screen shows the code and asks whether the host shows the same one, with two
  answers: Same code, or Different.
- The **host** screen shows the code too (the joiner's user compares against it), but its user
  does not answer with a button. They type the six digits the joiner's screen shows, and the
  host compares them with its own code locally, in constant time (spaces and hyphens between
  digits ignored). A match is the host user's confirmation; a mismatch can be typed again (the
  desktop allows three tries) and then counts as Different. Typing makes it impossible to
  confirm without a code on the other screen: when something else took the window, the real
  joiner shows an error, not a code, and there is nothing to type.
- Both screens show the other side's IP address, the host's as soon as the connection arrives.
- A joiner whose connection is refused or reset says that another device may have taken the
  window and that the host should cancel and open a new one.

This applies to every platform, phones included: whichever device hosts asks for the typed
code, and whichever joins shows Same code or Different.

| Type | Name | Direction | Payload |
|---|---|---|---|
| `0x01` | HELLO | joiner to host | `d(16)` \|\| `HMAC-SHA256(K, "ponydirect/id/v1" \|\| d)` |
| `0x02` | HELLO_ACK | host to joiner | `l(16)` \|\| `HMAC-SHA256(K, "ponydirect/id-ack/v1" \|\| d \|\| l)` |
| `0x03` | NO_MATCH | host to joiner | 48 random bytes |

`d` and `l` are 16 fresh random bytes. This is PonyDirect's LAN identify handshake
(PonyDirect WIRE-PROTOCOL.md) with `K` as its pair key; the table above is all of it.

- When the joiner's user confirms, the joiner writes the 4 ASCII bytes `PDR1` and HELLO. If
  its user says no, it sends ABORT 4 instead.
- The host reads the HELLO but does not answer it until its own user typed the matching code.
  Then it checks
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
in a million, and the window closes after that one try. A joiner user who confirms without
comparing is the only way through on that side, which is why the host's user must type the code
from the joiner's screen, and the joiner's screen says what a mismatch means.

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
checks and shows the item (section 6), and reports a RESULT for that id once its user decided.
A side may send another OFFER after the RESULTs for the previous one. BYE, or closing the
connection, ends the session; both sides then wipe `K`, `k_HJ` and `k_JH`.

Limits: one item is at most 64 MiB, one OFFER lists at most 1,000 items, and a side has at most
one OFFER outstanding.

The rules a receiver enforces (each break is a protocol error that ends the session):

- An OFFER while the previous OFFER from that side is unanswered, or before this side sent a
  RESULT for every id it accepted from it. A peer cannot swap the offer while the user is
  choosing.
- An ANSWER when this side has no OFFER waiting for one, or one that names an id the OFFER did
  not list (or names one twice).
- A RESULT for an id the other side did not accept.
- An ITEM_BEGIN for an id this side did not accept, or a second one for an id whose item already
  came.
- Any message between an ITEM_BEGIN and its ITEM_END other than ITEM_DATA for that id. A sender
  sends each item as one unbroken run: a message it has to send meanwhile (an ANSWER, a RESULT)
  waits until the ITEM_END is out.

Ending a session from the user interface never waits on the network: the implementation sends
BYE in the background and closes the connection after a short grace period (2 seconds)
whether or not BYE went out, so a peer that stopped reading cannot hold the app, and an item in
flight stops.

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

`fingerprint` is required for public-key and key-pair items. Before anything is written, the
receiver checks each received item against what the OFFER said:

- **public-key**: exactly one armored block holding exactly one certificate, with no secret key
  material, whose fingerprint equals the offered one.
- **key-pair**: exactly one armored block holding exactly one secret key whose fingerprint equals
  the offered one, every secret part with material protected by a passphrase.
- **backup**: a PGPony backup file (an armored, password-encrypted message).

An item that fails is not imported and its RESULT says why. An item that passes is shown to the
user as parsed from its bytes, not as the offer named it: the fingerprint and user IDs (and
whether it is already in the keyring) for a key, and for a backup what restoring it does. Only
when the user accepts that preview is anything written. A block with several keys is refused,
never imported in part. A backup that arrives by pairing restores its keys with no trust
levels: trust comes from this user's own decisions, never from the other device.

The receiver then imports through the same code as a file import or a restore, with every check
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
  dotted quad (no leading zeros) or an IPv6 literal in brackets, then `:` and a port from 1 to
  65535 (no leading zeros). The IPv6 literal is one of the text forms of RFC 4291 section 2.2:
  eight groups of 1 to 4 hex digits separated by `:`, or fewer with exactly one `::` standing
  for at least one zero group, optionally ending in a dotted quad (no leading zeros) for the
  last 32 bits. Nothing else: no zone (`%`), no white space, no single leading or trailing `:`.
  Names are refused, so an invite can never make the joiner look something up. IPv6 is written
  lowercase.
- The joiner turns each address into its 4 or 16 bytes with that grammar and connects to those
  bytes. It never hands the text to a resolver or to an API that would accept a name (on the
  JVM `InetAddress.getByAddress`, never `getByName`; on iOS `IPv4Address`/`IPv6Address` from
  bytes, never `NWEndpoint.Host(String)`).
- `h` is the first 16 bytes of SHA-256 of the host's window key, base64url with no padding:
  exactly 22 characters, and the 4 unused bits of the last one are zero (one spelling per
  hash).
- The scheme is matched without regard to ASCII case (no other case folding) and surrounding
  white space is trimmed.
  Members come in any order, separated by `&`; `a` and `h` must each appear exactly once,
  every member must have an `=`, and other members are ignored so a later version can add
  some. No percent-encoding: the characters above are all an invite uses.
- Any other version than `1`, or anything that breaks the rules above, is not an invite: the
  scanner says so and does nothing. Reading never throws, whatever the text.

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
A host passes each accepted socket's source address and its listed addresses' subnets to
`PairPeer.isAllowed` and closes the socket without a byte when it is not allowed (section 1);
the joiner connects with `PairInvite.Address.socketAddress()`, which never looks a name up.
End a session with `PairSession.endAsync()` from the UI, never `sendBye()` on the main thread.

**iOS.** The Swift package speaks the same bytes over an async transport; `NWPairTransport` wraps
an `NWConnection` and `NWPairListener` an `NWListener` (Network framework). The first LAN
connection shows the system's local network prompt, so `NSLocalNetworkUsageDescription` must be
in Info.plist, with text that says it is for pairing with another device (no Bonjour services
are declared: nothing is advertised). Scanning the invite needs the camera
(`NSCameraUsageDescription`). A pairing runs in the foreground only: iOS suspends sockets soon
after the app leaves the screen, so leaving ends it. Keep the idle timer off while it runs. The
app lists `backup` in `accepts` only once it restores a PGPony backup file from Android or
desktop. `NWPairListener` keeps off cellular interfaces and closes, without reading, any
connection whose source `PairPeer.isAllowed` refuses (its subnets come from the device's own
interfaces); `NWPairTransport.connect` builds its endpoint from the address bytes.

**Desktop.** Hosts and joins; shows the invite QR on the host screen and accepts a pasted
invite in the join field, where the key check applies as for a scan. The host's subnets are
those of the addresses its screen lists.

## 10. Test vectors

In `app/src/test/resources/pairing/`, checked by the Kotlin tests and by an independent Python
implementation when they were made. An implementation that does not reproduce them does not
speak this protocol.

- `v1-vectors.json`: one attempt's X25519 keys and nonces, the version byte, `commit`, `Z`,
  `T`, `K`, `k_HJ`, `k_JH`, `code`, and the first sealed message in each direction.
- `v1-session.json`: every byte of one whole session in both directions (handshake,
  confirmation, INFO, OFFER, ANSWER, one item, RESULT, BYE) with the randomness fixed, plus
  each phase 3 message on its own: sender, `seq`, plaintext, whole frame, and the parsed JSON.
  Replaying the script with the same random bytes must write exactly `host_to_joiner` and
  `joiner_to_host`. An implementation that writes its JSON members in another order matches
  the handshake prefixes and every listed frame (sealing the listed plaintexts), and parses
  every listed body; that is the bar.
- `v1-invites.json`: invites that must parse, with the addresses and hash they carry, the
  canonical form written back and (for some) each address's bytes, and invites that must be
  refused, each with the reason; among them bracketed strings that look like IPv6 but are not.
- `v1-peers.json`: a host's subnets, and connection sources it must let through to phase 1 or
  close (section 1).

## 11. Adding a platform

1. X25519, HMAC-SHA256, SHA-256 and AES-256-GCM, with HKDF written out as in section 3.
2. Reproduce `v1-vectors.json`, then the handshake prefixes and every frame of
   `v1-session.json`, then `v1-invites.json` and `v1-peers.json`.
3. Pair against desktop both ways (host and joiner), with a mismatched code on each side once
   (a wrong typed code on the host, Different on the joiner), and move one item of each kind
   the platform accepts.
4. Run the flows of section 9 and list the platform's `accepts` honestly.
