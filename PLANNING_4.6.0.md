# PGPony Android 4.6.0 — Planning

Status: planning (opened Sep 13 2026). Feature and fix list for the 4.6.0 cycle, seeded from
forum.dark.vegas user feedback. Android leads, then iOS mirrors each item once verified. Items are
detailed enough to build against; priorities and the RC breakdown are set once the list settles.

Context: the armor-comment onboarding toggle FreeDegenAuditor asked for (forum.dark.vegas, 31 Aug 2026)
already shipped in 4.5.0 rc3 as item 25 (Settings > Encryption toggle surfaced on the onboarding privacy
slide), so it is not a 4.6.0 item.


## 1. Key notes on the keyring list, and a reachable place to edit them

Priority: medium. Origin: SilverDefiFarmer (forum.dark.vegas, 0xf77e...17c7, 12 Sep 2026).

Reported: short local notes per key are useful for tying a key to a company or identity, especially when
the UID email is random or opaque (his example: label norsehorse@norsehor.se as "Pony" or "PGPony"). Two
concrete gaps: (a) a note can be added per key today, but it does NOT show on the keyring list screen, so
it can't act as the at-a-glance label he wants; (b) the add-note action sits at the bottom of Key Details,
so it is hard to find and reach.

What already exists: per-key notes are stored (PGPKeyEntity.notes, written via KeyRepository.updateNotes /
dao.update(key.copy(notes = ...))), and Key Details has a notes editor near the bottom. So this is a
surfacing and placement change, not new storage.

Work:

- Keyring list (KeyringScreen key row): when a key has a note, show it on the row as a local label, near
  the identity line, visually distinct from the UID (it is user-authored, not from the key). Truncate to a
  single line. Decide placement: under the name/email, or as a chip. Keys with no note render as today.
- Key Details: move the note edit affordance up to the identity area (near the top), instead of only at the
  bottom. Options: a small "add / edit label" control by the primary UID, or reorder the existing notes
  section higher. Keep the full editor, just make it reachable without scrolling to the end.
- Terminology: the user treats the note as a label/alias. Keep the single existing notes field (do not add a
  second field); just present it as a label on the list. If a distinct short "label" vs long "note" split is
  wanted later, scope it separately.

Research / unknowns:

- List truncation length and whether the label replaces or accompanies a random-looking email on the row.
- Whether a note should also be searchable / filterable in the keyring search (nice-to-have follow-on).
- iOS mirror: iOS KeyDetail has the same notes field; mirror both the list label and the reachable editor.

Delivery: a key with a note shows that note as a label on the keyring list, and the note editor is reachable
near the top of Key Details without scrolling to the bottom. Verified on device.


## 2. Import a public key from a URL, with a fingerprint check before it is added

Priority: medium. Origin: SwappingZkTrader (0x0b94...f3f3, 02 Sep 2026); verify-before-add refinement from
BanklessTechDev (0xd626...868c, 02 Sep 2026).

Reported: add an option to import a PGP key from a URL. And, before the key is actually added to the
keyring, display its fingerprint so the user can verify it is the key they expected (a manual trust check),
then confirm or cancel.

This is distinct from the existing keyserver lookup and from WKD (4.5.0 item 21): those resolve a key by
email/key-id from configured servers. This is fetching an arbitrary user-supplied URL (a raw .asc, a
key hosted on a site, a gist, a personal page).

Work:

- Entry point: an "Import from URL" action in the keyring import surface (alongside paste / file / scan).
- Fetch: reuse the existing proxy-aware HTTP client (the one KeyServerRepository / MultiKeyServerService use),
  so the fetch rides the offline switch and the Off/Orbot/Custom proxy setting for free. Enforce https (or warn
  loudly on plain http). Apply a response size cap. When offline mode is on, disable the action (same as
  keyserver lookups) rather than silently doing nothing.
- Parse: run the fetched body through ArmorExtractor (4.5.0 item 19) so a key embedded in an HTML page or with
  surrounding text still parses; handle a response carrying more than one key block.
- Verify-before-add sheet: after a successful fetch, show a confirmation sheet with the parsed key's
  fingerprint (full, monospace, groupable), primary UID(s), algorithm label, created/expiry, and a count if
  the response held multiple keys. The key is NOT written to the keyring until the user taps Add. Cancel
  discards it. This is the trust checkpoint BanklessTechDev asked for.
- On confirm: route through the normal import path (dedup / merge-on-matching-fingerprint, the same one paste
  and file import use), so a URL import of a key already held behaves like any other re-import.

Research / unknowns:

- HTTP redirects: follow within https only, cap the count, and verify the final content is a key, not an
  unrelated page.
- Whether to remember recently used import URLs (probably not, for privacy; leave it stateless).
- Security posture: an arbitrary-URL fetch is a network request from the app; it MUST go through the
  proxy-aware client, respect offline mode, and never auto-trust the fetched key. The fingerprint-verify sheet
  is the safeguard; the key gets no trust bump on import, same as any imported public key.
- iOS mirror: iOS already added the GitHub recipient-fetch-with-proxy pattern (AgePony 4.0.0 lineage / PGPony
  iOS), so an iOS URL import reuses that proxy plumbing.

Delivery: the user enters a URL, PGPony fetches it through the offline/proxy-aware client, shows the fetched
key's fingerprint and UID for verification before anything is stored, and only writes it to the keyring on
explicit confirm. Verified on device with a raw .asc URL and with a key embedded in an HTML page.


## 3. Offer ML-DSA-87 as a key-generation algorithm, paired with ML-KEM-1024

Priority: medium. Origin: Scott Lu (email, "PGPony Android Feedback (4.5.0)", Google Pixel 8, Android 17,
6:39 PM).

Reported: add ML-DSA-87 as an option when choosing the algorithm for key generation, paired with
ML-KEM-1024 as the default encryption key when generating the key pair.

What already exists: ML-DSA-87+Ed448 (KeyAlgorithm.MLDSA87_ED448_V6, algo 31) is a defined algorithm and is
already offered as a composite SIGNING SUBKEY (AddSubkeyChoice.PqSigning MLDSA87_ED448), and ML-KEM-1024+X448
(CompositeSuite.IETF_1024, algo 36) already generates both as an encryption primary and as an encryption
subkey. Two gaps remain for the primary composite-signing keygen: the picker list generatablePostQuantum in
KeyAlgorithm only carries MLKEM1024_X448_V6 and MLDSA65_ED25519_V6, so a composite ML-DSA-87 PRIMARY cannot
be generated from the UI; and CompositePrimaryKeyGen hardcodes the bundled encryption subkey to ML-KEM-768
(KEM_SUITE = IETF_768) regardless of the signing tier.

Work:

- Add MLDSA87_ED448_V6 to generatablePostQuantum so the primary keygen picker offers an ML-DSA-87 composite
  key alongside ML-DSA-65.
- Pair the bundled encryption subkey to the signing tier instead of hardcoding it: an ML-DSA-87 primary ships
  a ML-KEM-1024+X448 (IETF_1024) encryption subkey, an ML-DSA-65 primary keeps ML-KEM-768+X25519 (IETF_768).
  CompositePrimaryKeyGen.assemble takes the KEM suite from the chosen signing suite rather than the fixed
  KEM_SUITE constant.
- Thread the chosen signing suite from the keygen UI through the repository generate path into assemble.

Research / unknowns:

- Default vs option: Scott suggests ML-DSA-87 + ML-KEM-1024 as the default. These keys are much larger
  (ML-DSA-87 public material 2592 bytes, ML-KEM-1024 1568) and slower to generate and sign than the 65/768
  pair. Decide whether ML-DSA-65 + ML-KEM-768 stays the default with 87/1024 as an explicit stronger option,
  or 87/1024 becomes default. Leaning toward keeping 65 default and adding 87 as an option, since the larger
  keys cost size and speed for a security margin most users do not need yet.
- Size knock-on: larger keys affect armored export length and the QR export path (a 1024/87 public key may not
  fit a single scannable QR). Check the QR and share paths against the larger material.

Delivery: the key-generation picker offers an ML-DSA-87 composite primary, and generating one produces a
matching ML-KEM-1024 encryption subkey rather than a ML-KEM-768 one.

Refinement (Scott Lu, follow-up, 7:49 PM): frame the choice as two tiers rather than a single option. Keep
ML-DSA-65 + ML-KEM-768 as the DEFAULT for portability, speed, and already-ample security, and offer
ML-DSA-87 + ML-KEM-1024 as a max-security option with the larger, slower keys. That settles the default
question above: 65/768 stays default, 87/1024 is the explicit stronger opt-in.

Out of scope: Scott also suggested an even-lighter ML-DSA-44 + ML-KEM-512 tier. Those NIST levels exist, but
the OpenPGP PQC draft (draft-ietf-openpgp-pqc, the composite code points PGPony implements) registers
algorithm IDs only for ML-KEM-768, ML-KEM-1024, ML-DSA-65, and ML-DSA-87. There is no OpenPGP composite code
point for ML-DSA-44 or ML-KEM-512, so a 44/512 key would have no interoperable on-wire encoding and no other
OpenPGP tool could read it. Not viable until the spec registers those levels; revisit if it does.


## Delivery note

Android first per the new-feature procedure. iOS mirrors each item once the Android version is verified,
tracked separately. This document is seeded from the forum.dark.vegas thread; add further items here as they
come in before the 4.6.0 scope is locked.
