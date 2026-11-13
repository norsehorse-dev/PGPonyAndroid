# PGPony 4.8.0

New ways to make keys for security keys, trusted introducers, recipient groups, QR key exchange from #95, new
entry points from other apps, post-quantum SSH keys, Korean and Polish, and fixes across post-quantum signing,
security keys and keyring safety. 4.8.0 carries versionCode 480 and installs in place over 4.7.3 and the 4.8.0
release candidates. It went through eleven release candidates published as GitHub pre-releases, each with its own
signed tag; docs/RC_HISTORY.md lists them. The release adds one fix after RC11, the Usage row on ML-DSA keys
below, so its APK is a new build and not an RC file.

## Making keys

Generate Key, under Advanced, makes ECDSA keys on NIST P-256, P-384 and P-521, brainpoolP256r1, brainpoolP384r1,
brainpoolP512r1 and secp256k1, with an ECDH subkey on the same curve (#109). They are v4 keys. Security keys differ
in which curves they take, so check yours first. That group in the algorithm picker is now called "RSA, ECDSA and
LibrePGP".

Advanced: compose subkeys builds on the primary you pick: Ed25519 v6, Ed25519 v4, RSA, or ECDSA on any of the curves
above. It used to switch the key to Ed25519 v6. A v4 key can hold one ML-KEM-768 subkey, written as the v4 interop
subkey (algorithm 35); ML-DSA and ML-KEM-1024 need a v6 key. Include default encryption subkey names the subkey it
adds, and starts off when the list holds only post-quantum encryption subkeys, so a key composed as post-quantum only
comes out that way.

Primary certifies only is new in the composer, for security keys: the primary only certifies and stays off the card,
and signing, encryption and authentication go to subkeys. If you don't pick a signing subkey, one of the primary's
type is added.

An authentication subkey matches the primary: ECDSA on its curve, RSA of its size, Ed25519 otherwise. On brainpool
and secp256k1, Generate asks whether it is for a security key (the same curve) or for SSH (Ed25519), since SSH has
no key type for those curves.

Add subkey and the composer share one subkey picker. It asks what the subkey is for, its type, and its curve or
size, and opens on what fits the key: the first use the key doesn't have yet, on the primary's type and curve. It
offers ECDSA signing and authentication subkeys and ECDH encryption subkeys on every curve above. ML-KEM-768 is no
longer offered on an RSA or ECDSA key, where adding it failed, because its binding needs an Ed25519 primary.

ECDSA keys sign with a hash at least as long as their curve, as gpg does: SHA-384 for a 384-bit curve, SHA-512 for
brainpoolP512r1 and P-521.

## Post-quantum keys

A key with an ML-DSA signing subkey on an Ed25519 primary can sign. The composer and Add subkey on a v6 Ed25519 key
make these keys. Signing handed the ML-DSA subkey to Bouncy Castle, which can't use it, so a protected key failed as
a wrong passphrase and an unprotected one with "unknown public key algorithm". It now signs through PGPony's own
ML-DSA code, for every kind of signature and in mail apps, and those signatures verify and are credited to the key.
Reported by email.

Mail apps that use PGPony as their OpenPGP provider verify ML-DSA signatures, detached and clear-signed. Thunderbird
and other mail apps open mail encrypted to a passphrase-protected ML-KEM key: PGPony asks for the passphrase there,
and asks again after a wrong one, where it used to return an error. Reported by a user.

Key Details shows the Usage row for an ML-DSA key's primary, for example Certify, Sign. The row read the primary
through Bouncy Castle, which can't load an ML-DSA primary, so on those keys it was missing. Reported by email.

## SSH keys

Settings > Keys & Servers > SSH keys holds experimental post-quantum SSH login keys of the ssh-mldsa44-ed25519 type,
which pairs ML-DSA-44 with Ed25519. OpenSSH 10.6 turned this type on by default, and the server and your ssh client
both need 10.6 or later. A user asked for these by email.

They are kept apart from the OpenPGP keyring. Generate one with a label, or import a key file made with
`ssh-keygen -t mldsa44-ed25519`, with or without a passphrase. Copy or share the public key line for authorized_keys,
or export the private key as an OpenSSH key file under a passphrase, after the device check. Termux reaches them
through OkcAgent like PGPony's OpenPGP SSH keys. Backups and the pairing backup carry them. Key files from OpenSSH
10.4 and 10.5, which used the older name `ssh-mldsa44-ed25519@openssh.com`, import and are saved under the new name.
They are experimental because the IETF draft for this signature is still at its first revision; if the format
changes, a key may have to be made again.

## Security keys

Encrypting to a key picks its newest encryption subkey, as GnuPG does. PGPony took the first one listed, so a key
with several sent messages to its oldest encryption subkey, which may not be on the card (#108). Additional
decryption subkeys (ADSKs, GnuPG 2.4.1 and later) get their own copy of the session key, and PGPony decrypts with a
held ADSK; it read only the first byte of the key flags and never saw the ADSK flag (#108).

A security key decrypts through its authentication slot when the message is only for the key there and the card
supports MANAGE SECURITY ENVIRONMENT (OpenPGP card 3.3 and later). The decryption slot is still preferred when the
message has a copy for it (#108).

With the primary key on a security key, its edits are signed on the card with the PIN and a tap: add, make primary
or revoke a User ID, change the expiry of the primary or of an encryption subkey, Refresh self-signatures, revoke a
subkey, and Add subkey. A new subkey is made on the phone under a passphrase, and the sheet says to move it to the
card before you share the key. Add subkey works again on a key whose subkeys were moved to a card while the primary
stayed on the phone (#71).

Move to Security Key takes ECDSA and ECDH keys on the NIST, brainpool and secp256k1 curves, and decrypts on cards
that return the whole ECDH point. It works on a YubiKey NEO: a slot that already fits the key keeps its own settings,
as gpg does, where PGPony rewrote them and the NEO refused. A key the card can't take is refused before the PIN is
asked, and an error ends with the card's answer. Moving an RSA key into a slot that held a Curve25519 key works on
cards like the Token2, which wanted the modulus in the import. The NEO fix came from a tester's report.

## Trust

A key certified by one of your own keys at Ultimate trust shows as Verified, the way gpg treats it (#115). Only the
User IDs your key certified count, and Key Details names the key that vouched for it. When your Ultimate key
certifies a key with a trust signature (gpg tsign), that key's own certifications count too, down to the depth the
trust signature allows. A key you set to Unverified or Don't use never vouches for others, and a plain certification
by a key that isn't yours vouches for nothing, as in gpg without ownertrust. A key pair at Unknown is raised like a
public key.

## Recipient groups

A group is a named set of keys you add on the Encrypt tab in one step. Save the current recipients as a group from
the picker, or manage groups from the Keyring's menu under Groups. Key Details lists the groups a key is in. Picking a
group adds its usable keys and names any it left out, such as a revoked or expired key or one in Recently Deleted.
Full backups and full-backup pairing carry groups, and a restore merges them by name. The recipient picker lists your
own keys first, then everyone else A to Z.

## QR key exchange

Show Key on Exchange and the QR code on Key Details share one display, contributed in #95. Codes have a full quiet
zone and whole pixels per module, so cameras read them more easily. A code in several parts can use Larger dots, and
starts at one part a second, with Slower playback to switch back (#100). The scanner keeps every part it has read and
waits only for the missing ones, reads the area you aim at first, focuses where you tap, and says when the code
belongs to a different key or isn't a key.

PGPony reads PGPONY2, a QR format for public keys that rebuilds the key from most of its parts, so a few missed parts
no longer mean waiting for the loop to come round. It still sends the current format until PGPony for iOS and
Desktop read the new one (#95). A new setting, Long QR codes, under Encryption > Sharing, raises the limit from 32
parts to 512; codes over 32 parts only scan in PGPony Android 4.8.0 or later (#100).

The bottom bar has five tabs: Keyring, Encrypt, Decrypt, Exchange and Settings. Contacts opens from the Contacts
button at the top of Keyring.

## From other apps

Select text in another app and the menu offers Encrypt with PGPony and Sign with PGPony. In a field you can edit,
the result replaces the selection; otherwise PGPony shows it with Copy, Save and Share. A selection that is already a
PGP message, signed message or key opens the Quick Action (#103).

Share a file to PGPony and the Quick Action offers Sign a file, a detached .asc or .sig signature. Encrypting a shared
file has a Sign as row, set to None unless you pick a key (#72). A shared PGPony or OpenKeychain backup offers Restore
(#67). Verify a file takes several files and signatures in one pick and pairs them by name (#106). Files from a file
manager or Downloads whose address has no file name in it open (#98).

## Keyring and backups

A key can no longer end up in the keyring twice, and a key pair can no longer lose its private key that way. Imports
didn't look in Recently Deleted, so deleting a key, importing it again and restoring the deleted copy listed it
twice, and both copies shared the stored key material, so emptying Recently Deleted could remove it from the copy
still in use. Upgrading merges any duplicates already on the phone into one key, keeping the private key, card link,
notes and trust. Importing a key that is in Recently Deleted brings that key back, private key included.

Export Private Key asks for the key's passphrase after the fingerprint check, typed each time and checked by
unlocking the key, so a wrong one exports nothing. Backup asks for the fingerprint or screen lock check first. Done
after a backup or a restore goes back to the backup and restore choice (#113). Exported key files carry the key's
email between the name and the key ID, as in PGPony for iOS.

## Messages and files

A message whose first partial-length chunk is under 512 octets opens. Go's OpenPGP code writes smaller chunks, which
is how a Keybase signature failed here (#110). Decrypting a file works with text before or after the armor block, and
a clear-signed file with text around it verifies. Decrypting a file shows Save and Share only, without its content as
text. An inline signed message with a text signature stores CR LF line endings, which gpg checks. Settings has
Compress large files, off by default, for files over 16 MB (#104).

## Everyday use

- The keyboard's Done key unlocks on the passphrase prompt mail apps and SSH open, and runs the main action on the
  Encrypt and Decrypt passphrase dialogs (#105). Passphrase fields in Key Details open the keyboard and confirm with
  its action key (#86).
- Every text field asks the keyboard for its private mode, so it doesn't learn from what you type (#86).
- Every passphrase field has a show or hide toggle. Card PIN fields keep none. A passphrase typed for one attempt is
  cleared once that attempt starts on the screens 4.7.2 missed.
- Tapping outside a text field closes the keyboard on Generate Key, the Key Details sheets, Import, Pair, Settings and
  the Exchange import pane. Generate Key and other form sheets no longer close when swiped.
- A long press on a key starts select mode (#93). The Keyring menu has Reorder keys, and Settings can turn off drag
  to reorder (#101).
- Refresh self-signatures and the expiry confirmations let you pick SHA-256 or SHA-512. RSA keys of 3072 bits or more
  start on SHA-512 (#86).
- Check on Key Details asks your lookup key servers in order and names the first that has the key (#90).
- Keys PGPony has no name for, such as DSA with ElGamal, show their algorithm and size everywhere they are listed
  (#88).
- Settings > About shows the commit the build came from next to the version, and the build stays reproducible
  (#114). TapPony and HashPony are listed under More from NorseHorse.

## Languages

Korean and Polish are in the language picker. Korean covers every string, and #96 contributed seven of its error
messages. The Polish translation is mostly machine-made, checked against the terms Polish users know from GnuPG,
Kleopatra, Thunderbird and OpenKeychain; corrections are welcome in an issue or in the PGPonyTranslations
repository. The first language switch after the app starts changes the screen in place, without a black flash.

Pairing marks a skipped item as skipped whatever the phone's language; a phone set to Korean had its skips counted
as failed imports.

## For PGPony Desktop

The backup format is written up in docs/PGPONY_BACKUP_FORMAT.md, and the pairing skip check, the export file name
rule and the backup format constants are in code PGPony Desktop 4.0.0 shares.
