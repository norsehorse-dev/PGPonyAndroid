# Phase A1 — Subkey Model Refactor

## What this phase ships

The first user-visible v5.0 change: every key in the Keyring tab now
shows a chevron and can be tapped to expand a subkey list (algorithm,
capabilities, fingerprint, revoked/expired markers). Beneath the UI,
this phase adds:

- A new Room table `pgp_subkeys` with a `pgp_keys.id` foreign key
  (ON DELETE CASCADE) and indices on `primaryKeyId` and `fingerprint`.
- Four revocation columns on `pgp_keys` (`isRevoked`, `revokedAt`,
  `revocationReasonValue`, `revocationCertificate`) so Phase A6
  revocation work doesn't require another schema bump.
- A one-shot `SubkeyMigrationService` that walks every existing key
  on first launch after upgrade and populates the new table from the
  stored armored public-key material.
- A `MigrationProgressOverlay` Composable shown while the migration
  runs (most users won't see it — 10 keys parses in well under
  100ms).

### New files (6)

| File | Lines | Purpose |
|------|------:|---------|
| `app/src/main/java/com/pgpony/android/crypto/SubkeyCapability.kt` | 165 | Bit-flag enum + heuristic + BC wire-flag → ours mapper |
| `app/src/main/java/com/pgpony/android/data/PgpSubkeyEntity.kt` | 114 | Room `@Entity` for `pgp_subkeys` table + `PGPSubkeyDao` |
| `app/src/main/java/com/pgpony/android/data/migrations/Migration_1_2.kt` | 63 | DB v1 → v2 migration (CREATE TABLE + ALTER TABLEs) |
| `app/src/main/java/com/pgpony/android/data/SubkeyMigrationService.kt` | 189 | One-shot row-population job, gated on `subkeys_migrated` flag |
| `app/src/main/java/com/pgpony/android/ui/components/MigrationProgressOverlay.kt` | 156 | Full-screen Composable shown while the migration runs |
| `app/src/test/kotlin/com/pgpony/android/crypto/SubkeyCapabilityTest.kt` | 177 | 17 unit tests covering the pure bit-set, BC mapper, heuristic |

### Modified files (additive only)

| File | Before | After | Δ |
|------|------:|------:|--:|
| `app/src/main/java/com/pgpony/android/data/PGPKeyEntity.kt` | 143 | 194 | +51 |
| `app/src/main/java/com/pgpony/android/data/repository/KeyRepository.kt` | 232 | 328 | +96 |
| `app/src/main/java/com/pgpony/android/PGPonyApp.kt` | 62 | 116 | +54 |
| `app/src/main/java/com/pgpony/android/MainActivity.kt` | 260 | 290 | +30 |
| `app/src/main/java/com/pgpony/android/ui/keyring/KeyringViewModel.kt` | 254 | 274 | +20 |
| `app/src/main/java/com/pgpony/android/ui/keyring/KeyringScreen.kt` | 342 | 353 | +11 |
| `app/src/main/java/com/pgpony/android/ui/components/KeyCard.kt` | 164 | 286 | +122 |

**No original lines removed from any file.** Every structural element
from the originals (imports, sealed classes, data classes, public
functions, DAO methods, Composable signatures, navigation routes) is
preserved verbatim. Modifications are: (1) one bumped `version`
literal in `@Database(version = 1 -> 2)`, (2) one added entity in
the `entities` array, (3) one added abstract DAO accessor, (4) one
added (optional, defaulted-null) constructor parameter on
`KeyRepository`, and (5) two additive callsite updates that pass
`subkeys = state.subkeysByPrimaryId[key.id] ?: emptyList()` into
`KeyCard`.

## Architecture notes worth keeping

### Capability bit-set scheme

`SubkeyCapability` uses the iOS-compatible bit values:

```
Certify      = 0x01
Sign         = 0x02
Encrypt      = 0x04
Authenticate = 0x08
```

These DIFFER from the OpenPGP wire-protocol `KeyFlags` values (where
encrypt-comms is 0x04, encrypt-storage is 0x08, and authenticate is
0x20). `SubkeyCapability.fromBcKeyFlags()` does the wire → ours
mapping at the BC boundary; everything in our database stores in our
scheme. If we ever sync the keyring across iOS / Android the bit
values line up without translation.

### Migration is two-phase

1. Room's `Migration_1_2` runs as the database opens — synchronous,
   creates the table and ALTER TABLE adds the revocation columns.
2. `SubkeyMigrationService` runs after Room is ready, in a coroutine
   on `Dispatchers.IO`. It can't run inside the Migration because it
   needs `SecureKeyStore` (EncryptedSharedPreferences), which is not
   accessible from a `SupportSQLiteDatabase` context.

The service is gated on a `SharedPreferences` flag `subkeys_migrated`,
so it's a no-op on every launch after the first. `forceRebuild()` is
exposed for the future "reset subkey graph" Settings entry.

### Failure handling

A single bad key (missing material, corrupt armor, unrecognized
algorithm) is logged and skipped — the migration carries on and the
flag is still set on completion. The user can't get into a state
where one bad key blocks the rest of the keyring from showing
subkey details.

If the migration crashes entirely, `MainActivity` proceeds into the
app anyway (Failed state is treated as Complete for navigation
purposes). The flag stays unset, so the migration will be retried on
the next launch.

## Verified

- `SubkeyCapabilityTest` covers all bit-set helpers, the
  CERTIFY/SIGN/ENCRYPT/AUTH mappings from BC, the 0x20→0x08
  authentication-bit remap, the dual-encrypt-bit folding, and the
  heuristic fallback table for every supported `KeyAlgorithm`.
- `migrate(1 → 2)` SQL was hand-checked against what Room would emit
  for the `PgpSubkeyEntity` annotation (backtick identifiers, NOT
  NULL constraints, `ON UPDATE NO ACTION ON DELETE CASCADE`,
  default-zero literals, index naming `index_<table>_<col>`).
- All 7 modified files diff-clean: original line counts grew by 11
  to 122 lines each; no structural elements lost.

## Suggested entry for NorseHorse_Android_Update_Log.md

```
## PGPony Android Phase A1 — Subkey Model Refactor (2026-05-27)

First v5.0 feature ship. KeyCards now expand on tap to show a subkey
list (algorithm, capabilities, fingerprint, revoked/expired markers).
Plumbing-side, Room database bumped 1 -> 2 with the new pgp_subkeys
table + 4 revocation columns on pgp_keys.

### Added
- crypto/SubkeyCapability.kt -- bit-flag enum matching iOS scheme
  (Certify=1, Sign=2, Encrypt=4, Authenticate=8). Includes BC
  wire-flag mapper, heuristic fallback per algorithm, and self-sig
  KeyFlags reader.
- data/PgpSubkeyEntity.kt -- Room entity + DAO. FK to pgp_keys.id
  with ON DELETE CASCADE.
- data/migrations/Migration_1_2.kt -- CREATE TABLE pgp_subkeys, two
  indices, four ALTER TABLE ADD COLUMN on pgp_keys.
- data/SubkeyMigrationService.kt -- one-shot row populator, gated on
  SharedPreferences flag subkeys_migrated.
- ui/components/MigrationProgressOverlay.kt -- full-screen progress
  Composable shown while migration runs.
- SubkeyCapabilityTest (17 cases) -- pure unit tests for bit-set,
  BC mapping, heuristic.

### Modified (additive)
- data/PGPKeyEntity.kt: +51 lines (RevocationReason enum; 4
  revocation columns with defaults; @Database bumped to v2 +
  PgpSubkeyEntity + subkeyDao).
- data/repository/KeyRepository.kt: +96 lines (optional subkeyDao
  param; populateSubkeyRows hook on generate/import; getSubkeysFor
  query; CASCADE-aware delete comment).
- PGPonyApp.kt: +54 lines (addMigrations(MIGRATION_1_2); subkeyDao
  wiring; SubkeyMigrationService instantiation + appScope launch).
- MainActivity.kt: +30 lines (migration state observer; gate before
  onboarding check).
- ui/keyring/KeyringViewModel.kt: +20 lines (subkeysByPrimaryId
  map in UiState; load-loop in loadKeys()).
- ui/keyring/KeyringScreen.kt: +11 lines (pass subkeys list to
  KeyCard at both callsites; preserve TODO onClick).
- ui/components/KeyCard.kt: +122 lines (optional subkeys param;
  expand-on-tap; chevron icon; SubkeyRow Composable with star/arrow
  icons, capability label, fingerprint, revoked/expired markers).

### iOS port equivalents
- SubkeyCapability         = iOS SubkeyCapabilitySet (v5.0 Phase 1)
- PgpSubkeyEntity          = iOS PGPSubkeyModel @Model
- Migration_1_2            = iOS SwiftData migration plan v1->v2
- SubkeyMigrationService   = iOS SubkeyMigrationService.swift
- MigrationProgressOverlay = iOS MigrationProgressView.swift
- KeyCard expand-on-tap    = iOS KeyDetailView subkey section
  (iOS uses NavigationLink to a detail screen; Android uses inline
   expansion since there's no KeyDetailScreen yet -- TODO Phase A8)
```
