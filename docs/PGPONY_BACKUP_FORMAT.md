# PGPony backup format (`.pgpony`, format version 1)

What PGPony Android 4.8.0 writes and reads as a full backup, for the other apps that read or write
the same file (PGPony Desktop, PGPony iOS). The code is backup/BackupService.kt, with the entries in
backup/SshKeyBackup.kt and backup/RecipientGroupBackup.kt, the archive in backup/UstarArchive.kt and the
constants in backup/BackupFormat.kt.
The full-backup item of the pairing protocol (docs/PAIRING_PROTOCOL.md, section 6) is this same
file.

## 1. Container

- An OpenPGP message, symmetrically encrypted: AES-256, SEIPDv1 (no AEAD), iterated and salted S2K
  (no Argon2), the same shape `gpg -c` writes, so `gpg -d` opens it with the recovery code.
- ASCII armored, with the header `Comment: PGPony Backup v1`. Readers sniff that header to tell a
  PGPony backup from an OpenKeychain one.
- The passphrase is the recovery code: 24 Crockford base32 symbols (120 random bits), shown as six
  groups of four with hyphens. The S2K passphrase is the canonical form, uppercase with the hyphens
  removed (backup/CrockfordBase32.kt), so the code opens the file however the user types it.
- The file extension is `.pgpony`.

## 2. Archive

The decrypted payload is an uncompressed ustar archive. Entries, in this order:

| Entry | Since | Content |
| --- | --- | --- |
| `pgpony-meta.json` | 4.0.0 | Always first. See 2.1. |
| `keys/<fingerprint>.asc` | 4.0.0 | One per OpenPGP key. See 2.2. |
| `ssh-keys/index.json` and `ssh-keys/<hex>.key` | 4.8.0 | SSH-only keys. See 2.3. |
| `recipient-groups.json` | 4.8.0 | Recipient groups. See 2.4. |
| `pgpony-settings.json` | Android 4.x | Android settings. See 2.5. |

The rule every reader relies on: take the entries you know and skip the rest. Android 4.7.x reads
only `keys/*.asc` and the two JSON files it knows, and iOS ignores entries it does not know, so a
4.8.0 backup restores there with its OpenPGP keys, and a backup from before 4.8.0 restores in 4.8.0
unchanged. A new kind of data is added the same way: as a new entry, never by changing an existing
one.

A backup must hold at least one OpenPGP key or one SSH key.

### 2.1 pgpony-meta.json

```
{"appVersion": "4.8.0", "platform": "android", "createdAt": "<ISO 8601>", "formatVersion": 1,
 "keys": [{"fingerprint": "<lowercase hex>", "userID": "...", "algorithm": "...", "hasSecret": true,
           "trustLevel": "...", "contactLink": "<email, optional>", "createdAt": "<ISO 8601>",
           "expiresAt": "<ISO 8601, optional>"}]}
```

Descriptive only. A restore imports what the `keys/` entries hold and uses `userID` to name a key in
the restore report. It does not take trust levels from it: trust comes from the restoring user.

### 2.2 keys/<fingerprint>.asc

The primary fingerprint in lowercase hex with no spaces. The content is the armored key as PGPony
exports it: the secret key for a key pair whose secret is on the device, the public key otherwise
(a key on a security key or card goes as its public key). A restore is a merge: each entry goes
through the normal import, so a secret already held is never overwritten and a public-only key
gains its secret part.

### 2.3 ssh-keys/ (4.8.0)

```
ssh-keys/index.json   {"formatVersion": 1, "keys": [{"fingerprint": "SHA256:...", "label": "...",
                       "createdAt": <epoch ms>, "file": "ssh-keys/<hex>.key"}]}
ssh-keys/<hex>.key    the key as an unencrypted OpenSSH private key file (openssh-key-v1,
                       comment = label); <hex> is the hex SHA-256 of the public key blob
```

The index comes first, then one file per key. The files need no passphrase of their own because the
whole archive is encrypted; a user who opens the backup with gpg and tar can use them with ssh
directly. The keys are of the type ssh-mldsa44-ed25519 (OpenSSH 10.6 name); a reader that does not
support a key's type reports it as left out.

Restore merges by the key's fingerprint: a key already held is unchanged, a new key is added, and a
file that does not read is reported by its label as failed without stopping the rest. A file the
index does not name (or a damaged index) still restores, with the file's comment as its label.

A key the writer could not read on its own device is not written; the writer tells its user how
many were left out.

### 2.4 recipient-groups.json (4.8.0)

```
{"formatVersion": 1, "groups": [{"name": "Family", "createdAt": <epoch ms>,
                                 "members": ["<lowercase hex primary fingerprint>", ...]}]}
```

- Written: only members whose key is in the same backup, and no group that is left with none.
- Restored after the keys are in. Groups merge by name, ignoring case: a group with a new name is
  added (unless it would be empty), and a group with a name already on the device gains the members
  it lacks. Only members whose key is on the device, live or in Recently Deleted, are kept.
- A reader takes the fields it knows and ignores the rest, so a later version can add fields.
- The restore report lists the groups added and the groups that gained members.

### 2.5 pgpony-settings.json

```
{"formatVersion": 1, "proxy": {"mode": ..., "customHost": ..., "customPort": ..., "onionMirror": ...},
 "keyservers": [...]}
```

Android's network settings. A restore offers to apply them; other apps may ignore the entry.

## 3. Pairing

The pairing `backup` item is this file under a recovery code made for the transfer, so it carries
SSH keys and recipient groups like a saved backup. See docs/PAIRING_PROTOCOL.md, section 6.
