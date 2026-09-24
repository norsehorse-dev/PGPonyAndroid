# PGPony 4.2.0

The largest release since 4.0.0, shaped over six release candidates by the
people in the issue tracker. Thank you to everyone who tested, reported,
and retested.

## Post-quantum

- The ML-KEM 1024 hybrid suite joins 768, interoperating with GnuPG 2.5.x
  in both directions (#1). The 1024 suite pairs ML-KEM with X448 inside
  the composite key.
- File decryption with composite (v5/v6 PQC) keys is fixed. File decrypt
  used a separate code path that did not understand composite keys, so
  files encrypted to them would not open at all (#33).

## If you generated a 768 key before 4.2.0

Early 768 composite keys carry an encoding gpg cannot encrypt to. The
keyring shows a notice on affected keys and the app will suggest
regenerating them. Keys generated in 4.2.0 or later are not affected.

## Large files and bundles

Encryption and decryption now stream from disk end to end. A file or
bundle is never held in memory whole, at any size, in any of the ways
content enters the app: File mode, Bundle mode, or sharing from another
app (#32, and the remaining large-file case of #33). Very large encrypted
.eml files, which previously could not be decrypted at all past a few MB,
decrypt now. Practical note: mail servers refuse attachments far below
these sizes; a very large bundle travels as a file, not as email.

## Key management

- Multiple identities (user IDs) per key, with add and revoke (#29).
- Subkeys are displayed per key, and new subkeys can be added (#25).
- Per-key fallback decryption keys: older keys can be enabled, in your
  order, as fallbacks for a newer key, with an optional strict mode that
  disables the compatibility net (#34).
- Per-key signing defaults: choose which key signs on behalf of another
  for PQC recipients, classical recipients, and sign-only, so pre-v6
  recipients can verify your mail while your primary key stays modern
  (#34, #22).
- Change of import verification: the import preview shows the complete
  fingerprint in standard four-character groups (#35).

## Mail client interoperability

Clients without v6/composite support (OpenKeychain, and K-9 for import)
cannot read messages addressed to composite keys. The signing defaults
above exist for exactly this. When a signing substitution is active and
your own key is among the recipients, encrypt-to-self follows the
substitute key, so a Thunderbird sent-folder copy stays readable and
pre-v6 recipients receive mail they can open (#34). Thunderbird 21.1+
handles v6 directly.

## Safeguards

After a tester permanently lost three keys, deletion got serious
friction. Deleting a key pair offers a backup first, requires an explicit
acknowledgement, and asks for biometric or device credential whenever the
device supports it (#21, #36). Clear All Data lists every key it will
destroy, requires two acknowledgements, a typed confirmation word, a
five-second countdown, and biometric, then resets the app to first-run
like a fresh install (#16).

## Settings and UI

- Settings reorganized into category pages.
- Passphrase cache duration is configurable: 1 minute to 1 hour, or until
  cleared (#15).
- Font scaling fixes: key creation and other sheets are fully usable at
  large font sizes (#23).
- Shared-file encryption results have a proper Save button and cleaner
  layout (#13), save confirmations show in green, and assorted small
  fixes from the RC cycle (refresh indicator, biometric lock switch state
  after onboarding).
- Localization pass across German, Spanish, French, Japanese, and
  Brazilian Portuguese.

## iOS

Feature parity with this release lands in PGPony iOS 8.2.0.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
59a0aa492982072d81c2ccd706d5d7096758c999a7ad065354e191b126563e2a
```

Content hash (for rebuilders; excludes signature, see
REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
eae3f95d80391cf73779d58ebb435a407f07efb9ade102eede5e67c2720daced
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is
attached to this release.
