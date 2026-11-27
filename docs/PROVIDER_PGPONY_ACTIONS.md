# PGPony's own OpenPGP provider actions

Status: PGPony API level 1, PGPony Android 4.8.2. A published contract: actions and extras are
only ever added. A name is never renamed, and an extra never changes meaning; a change that
would need either gets a new name and a higher API level.

PGPony's OpenPGP provider answers the standard OpenPGP API (`IOpenPgpService2`, the actions in
`OpenPgpApi`). It also answers a few actions of its own, named `com.pgpony.android.action.*`, on
the same binding. The first ones give an app raw X25519 key agreement with the user's own
Curve25519 encryption subkeys, so StegPony can reveal with a key held in PGPony, on the phone or
on a security key.

Where it lives:

| | |
|---|---|
| Names and extras | `app/src/main/java/com/pgpony/android/provider/PGPonyActions.kt` |
| Service | `PGPonyOpenPgpService.kt` (`capabilitiesResult`, `x25519Keys`, `x25519Agree`) |
| Confirmation, key on the phone | `ProviderX25519Activity.kt` |
| Confirmation, security key | `ProviderCardOpActivity.kt` (`x25519OnCard`) |
| Checks, agreement, card answer | `crypto/X25519Agreement.kt`, `crypto/X25519Subkeys.kt` |
| Tests | `app/src/test/kotlin/com/pgpony/android/crypto/X25519AgreementTest.kt` |
| Test client | PGPonyApiTest, tests 6 to 9 |

## 1. Calling

Bind and call exactly as for any OpenPGP API action: `IOpenPgpService2.execute(data, null, 0)`
(these actions use no input or output pipe), with `OpenPgpApi.EXTRA_API_VERSION` set to a version
PGPony accepts (7 to 12). Before dispatch, every call goes through the same steps as the
standard actions:

1. The API version gate. Outside 7 to 12: `RESULT_CODE_ERROR`, `INCOMPATIBLE_API_VERSIONS`.
2. The caller is the package of the binder uid, never an extra.
3. The signature-pinned allow-list (Settings, Connected apps). An app not yet allowed gets
   `RESULT_CODE_USER_INTERACTION_REQUIRED` with a `PendingIntent` to PGPony's consent screen; a
   signature that no longer matches the allowed one gets an error.

Results use the standard extras: `OpenPgpApi.RESULT_CODE` (`RESULT_CODE_SUCCESS`,
`RESULT_CODE_ERROR`, `RESULT_CODE_USER_INTERACTION_REQUIRED`), `OpenPgpApi.RESULT_ERROR` (an
`OpenPgpError`, `GENERIC_ERROR`, with a message for people) and `OpenPgpApi.RESULT_INTENT` (the
`PendingIntent`). An error result of a PGPony action also carries
`com.pgpony.android.extra.ERROR_REASON`, a stable string for code (section 5).

PGPony 4.8.1 and older answer every action they don't know with `RESULT_CODE_ERROR`,
`GENERIC_ERROR`, "Unknown OpenPGP API action: ...". So that answer to `GET_CAPABILITIES` means
"no PGPony actions here".

## 2. `com.pgpony.android.action.GET_CAPABILITIES`

No request extras. Success, with:

| Extra | Type | |
|---|---|---|
| `com.pgpony.android.extra.CAPABILITIES` | `String[]` | The PGPony actions this build answers: `com.pgpony.android.action.X25519_KEYS`, `com.pgpony.android.action.X25519_AGREE` |
| `com.pgpony.android.extra.API_LEVEL` | `int` | 1 |
| `com.pgpony.android.extra.X25519_MAX_POINTS` | `int` | The most points one `X25519_AGREE` call takes: 32 |

No key data, no confirmation.

## 3. `com.pgpony.android.action.X25519_KEYS`

No request extras. Success, with parallel arrays, one entry per subkey:

| Extra | Type | |
|---|---|---|
| `com.pgpony.android.extra.X25519_SUBKEY_FINGERPRINTS` | `String[]` | Subkey fingerprint, upper-case hex, 40 digits (v4) or 64 (v5, v6) |
| `com.pgpony.android.extra.X25519_PRIMARY_FINGERPRINTS` | `String[]` | The primary key's fingerprint |
| `com.pgpony.android.extra.X25519_PUBLIC_POINTS` | `byte[]` | The 32-byte public u-coordinates, concatenated in the same order |
| `com.pgpony.android.extra.X25519_LABELS` | `String[]` | The key's primary User ID, for showing to the user |
| `com.pgpony.android.extra.X25519_ON_CARD` | `boolean[]` | True when the subkey is on a security key |

The list holds the user's own Curve25519 encryption subkeys that are usable now:

- Curve25519 only: v4 (and LibrePGP v5) ECDH on Curve25519Legacy (algorithm 18, OID
  1.3.6.1.4.1.3029.1.5.1, point `0x40 || u`), and X25519 (algorithm 25, a bare `u`). The point
  given is the 32-byte u-coordinate in the RFC 7748 encoding either way, so an age recipient is
  built from it directly.
- Bound by the primary with a binding in force, not revoked, not expired, under a primary that
  is not revoked or expired, and marked for encryption (or as an additional decryption subkey).
- On a key pair, only subkeys whose secret is on the phone (not a stub). On a key on a security
  key, the subkeys in its decryption or authentication slot.

Public data only, so the allow-list is the gate: no confirmation. An empty list is a success.

## 4. `com.pgpony.android.action.X25519_AGREE`

Request:

| Extra | Type | |
|---|---|---|
| `com.pgpony.android.extra.X25519_SUBKEY_FINGERPRINT` | `String` | The subkey, as `X25519_KEYS` lists it (case, spaces and colons don't matter) |
| `com.pgpony.android.extra.X25519_POINTS` | `byte[]` | 1 to 32 points of 32 bytes each, concatenated |
| `OpenPgpApi.EXTRA_PASSPHRASE` | `String` | Optional, as `DECRYPT_VERIFY` takes it |

Success:

| Extra | Type | |
|---|---|---|
| `com.pgpony.android.extra.X25519_SECRETS` | `byte[]` | One 32-byte shared secret per point, X25519(subkey secret, point), concatenated in the same order |

### The call sequence

Every agreement needs the user's yes for that call. PGPony never remembers a yes.

1. The client calls with the request. PGPony checks it (section 5), parks it, and returns
   `RESULT_CODE_USER_INTERACTION_REQUIRED` with a `PendingIntent`.
2. The client starts it with `startIntentSenderForResult`. PGPony shows a dialog naming the
   calling app, the key (its User ID and the subkey fingerprint) and the number of agreements.
   - Key on the phone: Allow, with a passphrase field when the key is protected and neither
     `EXTRA_PASSPHRASE` nor PGPony's passphrase cache has its passphrase. A passphrase typed
     there is cached as the provider's decrypt caches one (Settings, how long PGPony remembers
     passphrases). The provider's decrypt has no biometric step, and neither does this.
   - Security key: the card PIN, then a tap over NFC or Use USB key. PGPony checks that the card
     holds the subkey (decryption slot, or authentication slot on a card that supports MANAGE
     SECURITY ENVIRONMENT) before the PIN is sent, then runs PSO:DECIPHER once per point, the raw
     32-byte point in the Cipher DO. A card that answers `0x40 || secret` is read as the secret.
3. On Allow, PGPony computes the result and returns `RESULT_OK` with the client's request intent
   echoed back. Cancel returns `RESULT_CANCELED`, and the parked request is dropped.
4. The client calls `execute` again with the returned intent. PGPony answers from the stored
   result: `X25519_SECRETS`, or the error that stopped it.

The stored request and result are keyed by a SHA-256 of the action, the calling package, the
subkey fingerprint and the points. They live five minutes and are handed out once: a second
re-call starts over at step 1, and another app, or the same app with other points, never matches
a stored result.

### Checks and secrets

- Points are exactly 32 bytes. The small-order u-coordinates and the non-canonical forms of 0
  and 1 (libsodium's list of seven, with bit 255 ignored) are refused before any key is touched.
- An all-zero shared secret, or a card answer that isn't one, fails the whole call. No partial
  result is returned.
- The scalar and every shared secret PGPony holds are wiped after use; a result nobody collects
  is wiped when it expires. Points, secrets and keys are never logged.

## 5. Error reasons

`com.pgpony.android.extra.ERROR_REASON` on an error result of a PGPony action:

| Reason | When | Returned |
|---|---|---|
| `invalid_request` | Missing or malformed fingerprint; no points; points not a multiple of 32 bytes | at once |
| `too_many_points` | More than 32 points | at once |
| `low_order_point` | A point of small order | at once |
| `unknown_key` | None of the user's keys has that subkey | at once |
| `unsupported_key` | The user has that key, but it is not a Curve25519 encryption subkey | at once |
| `key_unavailable` | A Curve25519 subkey that can't be used now: revoked, expired, not bound for encryption, its secret not on the phone, or on a card slot the card can't decrypt with | at once, or on the re-call |
| `agreement_failed` | An all-zero shared secret, or a card answer that isn't one | on the re-call |

A wrong passphrase or PIN is handled in PGPony's dialog and never reaches the client. Cancel is
`RESULT_CANCELED` from the `PendingIntent`, not an error result.

## 6. Example (Kotlin)

```kotlin
val request = Intent().apply {
    action = "com.pgpony.android.action.X25519_AGREE"
    putExtra(OpenPgpApi.EXTRA_API_VERSION, 12)
    putExtra("com.pgpony.android.extra.X25519_SUBKEY_FINGERPRINT", subkeyFingerprint)
    putExtra("com.pgpony.android.extra.X25519_POINTS", points)
}
val reply = service.execute(request, null, 0)
when (reply.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
    OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED -> {
        val pi = reply.getParcelableExtra<PendingIntent>(OpenPgpApi.RESULT_INTENT)!!
        startIntentSenderForResult(pi.intentSender, REQUEST_AGREE, null, 0, 0, 0)
    }
    OpenPgpApi.RESULT_CODE_SUCCESS ->
        use(reply.getByteArrayExtra("com.pgpony.android.extra.X25519_SECRETS")!!)
    else -> fail(reply.getStringExtra("com.pgpony.android.extra.ERROR_REASON"))
}
```

In `onActivityResult`, on `RESULT_OK`, call `service.execute(data, null, 0)` with the returned
intent and read `X25519_SECRETS` from that reply.
