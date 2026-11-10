# Before PGPony Desktop 4.0.0 starts: changes in PGPonyAndroid 4.8.0

Status: Nov 9 2026, written while 4.8.0 is being finished (RC9 is the latest tag).

Done in 4.8.0 RC10 (Nov 9): sections 1 and 2 in full, the optional "skipped" member included. The backup format
is docs/PGPONY_BACKUP_FORMAT.md (a name outside the BACKUP_FORMAT*.md ignore pattern, which keeps the old
private notes out of git).

Desktop 4.0.0 vendors every shared tree from the v4.8.0 tag (PLANNING_DESKTOP_4_0_0.md) and never edits a vendored
file by hand. So a change desktop needs in shared code has to be on main before v4.8.0 is tagged. Otherwise desktop
waits for 4.8.1 or takes a recorded exception in its vendor/README.md.

What was checked: every file added or changed since v4.7.3 under crypto/, data/, backup/, network/, pair/ and lock/,
for imports desktop cannot compile; the new unit tests in those trees; and the 4.8.0 items that say desktop takes
something from the sync.

## 1. Code, before the tag

### 1.1 Move the pairing skip check into pair/

PairSkip (the KNOWN list of skip reasons and isSkip) lives in ui/pair/PairLedger.kt, which desktop does not vendor.
Protocol v1 has no flag for a skip, so both apps have to recognize the other's reason text, in every language
either ships. With the list in ui/, desktop keeps its own copy and has to follow every change to it by hand (RC9
added the Korean text Android really sends, and Polish).

Work: move PairSkip to pair/PairSkip.kt, move only (internal becomes public so desktop can call it). PairLedger keeps
calling it. Move the skip cases of ui/pair/PairLedgerTest.kt to a test in test/.../pair/, which desktop already
syncs.

Optional in the same change, the carried 4.7.0 item 21 remainder (section 6 of PLANNING_4.8.0.md): an optional
`"skipped": true` member on RESULT, sent next to the reason text. A receiver that sees it counts a skip without
matching any text, and the text list stays for apps that do not send it. PAIRING_PROTOCOL.md gets the member.

If neither lands in 4.8.0: desktop's Polish skip reason (d_pair_skipped_reason) must be exactly "Pominięte przez
drugiego użytkownika", so 4.8.0 phones count a skip from a Polish desktop as a skip.

### 1.2 Move the export file name rule out of ui/

buildExportFilename (item 4h, the email between the name and the key ID) is in ui/keyring/KeyShareIntents.kt. Desktop
names its exports itself and would copy the rule. Move it, move only, to a shared tree (for example
crypto/ExportFilename.kt), with ui/keyring/ExportFilenameTest.kt moving to the matching test tree. KeyShareIntents
keeps calling it.

### 1.3 Move the backup constants out of BackupService (found Nov 10, after RC10)

backup/BackupFileSniff.kt (RC5, #67) named BackupService.FILE_EXTENSION, and its test BackupService.ARMOR_COMMENT.
BackupService.kt is excluded on desktop, so the vendored file would not compile there. The check above read
imports, and this is a same-package reference with none. Done on main after RC10: ARMOR_COMMENT, FORMAT_VERSION and
FILE_EXTENSION live in backup/BackupFormat.kt (plain Kotlin, no imports), BackupService's companion keeps the three
names as aliases for the app's callers, and BackupFileSniff and its test read BackupFormat. Values unchanged.

## 2. Docs, before the tag

### 2.1 Write down the backup format

Desktop's backup service is its own code (BackupService.kt is excluded there) and its header cites
BACKUP_FORMAT_4_0_0.md, which is in neither repository. 4.8.0 adds two entries, so desktop and iOS need the format in
writing. Write docs/PGPONY_BACKUP_FORMAT.md:
- The container (armored, password-encrypted message, Comment: PGPony Backup v1) and the recovery code.
- The ustar entries: pgpony-meta.json first, keys/<fingerprint>.asc, pgpony-settings.json.
- recipient-groups.json (new in 4.8.0): formatVersion 1, name, createdAt, members by lowercase primary fingerprint,
  only members whose key is in the backup; a restore merges by name after the keys are in and keeps only members
  whose key is on the device. As RecipientGroupBackup.kt writes and reads it.
- ssh-keys/ (new in 4.8.0): what SshKeyBackup.kt writes, and the merge by fingerprint on restore.
- The rule older apps rely on: a reader takes only the entries it knows and skips the rest (4.7.x reads only
  keys/*.asc and its two JSON files).

### 2.2 Pairing: what a backup item carries

PAIRING_PROTOCOL.md: a `backup` item sent by 4.8.0 can carry groups and SSH keys, and Android's backup count
includes SSH keys. Say how a receiver that does not hold SSH keys reports them (left out and named, not counted as a
failure), so desktop's tally matches the phone's.

### 2.3 Two corrections in PLANNING_4.8.0.md

- 4n says desktop takes "the data layer and the backup and pairing format from the sync". Desktop takes data/groups/
  and backup/RecipientGroupBackup.kt from the sync, but its backup service and its database migrations are its own
  code (BackupService.kt and RoomMigrations.kt are excluded on desktop), so it wires those itself.
- 4p says "Desktop mirrors it (done separately)". Not done on desktop yet: KeyToCard's attribute plan comes with the
  sync, and desktop's own Read card change (6A83 handled like 6A88 on the optional reads) is desktop 4.0.0 work.

## 3. Checked, no Android change needed

- Every new file under data/, backup/ and crypto/ is plain Kotlin and JDK except data/ssh/SecureSshKeyVault.kt, which
  uses SecureKeyStore (already excluded on desktop). SshKeyStore takes the SshKeyVault interface, so desktop excludes
  the Android vault and implements the interface over its KeyMaterialStore.
- data/CertifiedTrust.kt imports androidx.compose.runtime.mutableStateOf, which Compose Desktop provides.
- RoomMigrations.kt stays excluded on desktop. The merge in MIGRATION_12_13 is planned by DuplicateKeyRows (plain
  Kotlin) and the groups SQL is RecipientGroupSchema.MIGRATION_13_14, so desktop's own 12 to 13 and 13 to 14 steps
  call the same code.
- The new tests under backup/, data/, data/groups/, data/ssh/ and crypto/ssh/ use no Android classes. Desktop adds
  the backup/ and data/ test trees to its sync script.
- The strings desktop's new screens need (groups, SSH keys) and Polish are in values-*/ in every locale after RC9.
