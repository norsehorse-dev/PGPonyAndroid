# PGPony 4.5.0 for Android

4.5.0 is the release where post-quantum encryption becomes something you actually use, not just something the app can technically hold. You can generate a fully post-quantum key, add post-quantum encryption to a key you already own, and the app is honest with you about when a message is protected against a future quantum attacker and when it is not. Around that sit real key management, a round of security hardening from an outside review, smartcard support for NIST P-521, and a batch of fixes from tester reports.

Most of this came out of the 4.4.x tester cycle. Where a public issue drove a change, it is credited by handle and number.

## Post-quantum encryption you can rely on

**Post-quantum-only keys.** You can now generate a key that is post-quantum from top to bottom: a composite ML-DSA signing primary and a composite ML-KEM encryption subkey, with no classical key anywhere on it. Before this, a post-quantum key still carried a standalone classical X25519 encryption subkey, which is a downgrade path. A sender that encrypts to every subkey (sequoia does this by default) would wrap the message under the breakable classical key even though the post-quantum subkey was right there. A post-quantum-only key has nothing to downgrade to. Compatibility keys stay the default, since most people you write to are still on classical keys, and post-quantum-only is the deliberate choice for when you want no weak link. Origin: Umotas (#36).

**The interoperable v4 shape.** Full v6 post-quantum support is still thin across other software and will stay that way for a while. RFC 9980 defines a middle path: an ordinary v4 Ed25519 key carrying a v4 ML-KEM-768+X25519 (algorithm 35) encryption subkey. The signing primary is a plain v4 key every tool already understands, and only the encryption subkey needs post-quantum awareness. That makes it the standardized common denominator for adding post-quantum encryption without forcing your correspondents onto v6. PGPony now generates it, validated against the RFC 9980 Appendix A.2 test vectors, and it advertises the right feature flags so a capable sender picks the post-quantum subkey instead of downgrading. Origin: hko-s (#56).

**Mixed-recipient warning.** OpenPGP wraps one session key per recipient, so a message is only post-quantum confidential if every recipient has a post-quantum key. One classical recipient makes the whole message recoverable by a future quantum attacker through that person. When you pick a recipient set that mixes post-quantum and classical keys, PGPony now shows a non-blocking warning that names the classical recipients, so the weak link is visible before you send. Origin: Umotas (#36).

**Post-quantum subkeys on existing keys.** You no longer have to start over to go post-quantum. You can graft an ML-KEM encryption subkey onto a key you already own, a v6 key directly or a v4 key converted to the interop shape, and add a composite ML-DSA signing subkey. An advanced granular mode, behind a toggle, lets you pick the exact subkey set rather than taking a fixed template. Origin: elnardosa (#55).

**Composite keys as first-class keys.** A composite ML-DSA key can now carry more than one User ID, and it works as an encryption recipient through its ML-KEM subkey. Importing a key generated in sequoia-sq (ML-KEM-768 or ML-KEM-1024) and decrypting messages sent to it works end to end, including the protected-key and file paths that had gaps before. Origin: Umotas (#36), WundreLust (#57), and tester follow-ups.

## Key management

**Delete or revoke subkeys.** You can retire a subkey two ways now, and the app makes the difference clear. Remove from keyring strips the subkey locally, which is right for one you generated but never shared. Revoke issues a proper revocation signature with a reason, so people who already hold your key see the subkey as retired and stop encrypting to it, which is the correct way to retire a subkey that has been published. There are guard rails against removing or revoking your last encryption subkey. Origin: user request, with revoke feedback from AraafRoyall (#36).

**Revoke instead of delete, from the delete sheet.** Deleting a whole key pair now offers "revoke instead" right in the delete dialog, since you cannot make a revocation certificate after the key is gone. Origin: CertainBot (#36).

**Custom key servers and Web Key Directory.** You can point the app at your own key server repositories, add and remove them in Settings, and look up and publish through them. They ride the offline and proxy switches like the built-in servers. Web Key Directory, which was always the first lookup source, now appears in the Settings key-server list with its own on/off toggle, so the screen matches what the app actually does. Origin: repeated requests (#55).

**Encrypt to a shared key, not just import.** When someone shares a public key into PGPony, you now get an "encrypt to this key" option, not only import, since encrypting to it is often the reason it was shared. Origin: CertainBot (#58).

**Per-recipient subkey selection.** When a recipient's key offers more than one encryption target, you get a dropdown to choose which one, defaulting to the automatic pick so single-subkey keys are unchanged. Origin: AraafRoyall (#36).

**Key generation without an email.** A User ID does not have to be "Name <email>". You can generate a name-only key now. The email field is optional, and a name-only key simply does not offer to publish to key servers, since they discover by email.

**Truthful key labels.** NIST and brainpool curve keys were being labeled "RSA 4096" because the detector fell back to that for anything it did not model. It now reads the actual curve and reports NIST P-256/384/521, brainpool, secp256k1, and the 25519/448 curves, and a key it genuinely cannot model reads "Unknown" instead of a confident wrong label. ML-KEM-1024 and the RSA sizes (3072, 8192) are labeled correctly too. Origin: Google Play review, elnardosa (#55).

## Security

**Hardening from an outside review.** An independent review found several pre-authentication denial-of-service issues in the decrypt path, all fixed. A crafted password-encrypted message could set an Argon2 memory parameter that forced a multi-gigabyte allocation before the password was even checked; there is now a hard ceiling enforced before any unlock. A small compressed payload could inflate to gigabytes or overflow the stack through deep nesting; the decrypt path now caps both depth and total size. Signature verification respects revocation, expiry, and key flags, so a signature from a revoked, expired, or non-signing key no longer shows as verified. And every SEIPDv1 decrypt failure now collapses to one error type, closing a weak oracle.

**One switch for destructive actions.** Deleting a key, removing a subkey, and clearing all app data now sit behind a single Settings > Security switch that requires device authentication, on by default. Origin: AraafRoyall (#36).

**Offline and publish.** The offline-mode switch moved to the top of Settings > Security, where it belongs given how central it is. Key generation no longer offers to publish your new key while offline mode is on, the online publish step has a clear "Not now", and you can turn off the suggestion to publish to pgpony.app entirely, keeping with the app's no-server-by-default posture.

## Smartcard

**NIST P-521 on a card.** Decryption with a nistp521 secret key on a SmartPGP JavaCard now works. The card command that carries the ephemeral key was written assuming a short-form length field, which a 521-bit key's 133-byte point overflows, and the key-derivation step used a fixed curve identifier. Both are fixed, the other NIST curves are covered, and it was confirmed on real hardware by the reporter. Origin: wreps8Owt (#62).

## Fixes

A file encrypted to an imported composite ML-KEM key failed to decrypt while the same message pasted as text worked; the file path was not handing the imported key to the part that opens the ML-KEM subkey. Fixed, with a regression test built from the reporter's own key and file. Umotas (#36).

Multi-recipient messages to post-quantum keys could fail to decrypt for one recipient while working for another, on both the IETF and LibrePGP composite paths, and a classical recipient of a mixed message could fail because the message still carried a composite packet the underlying library cannot parse. All three are fixed. WundreLust (#57) and tester follow-ups.

Adding a second email to a key set the new address as primary once the key was uploaded, even when it was not marked primary. A freshly generated key's first address is only implicitly primary, so the newer self-signature won on the server. Adding a non-primary address now pins the original explicitly.

A post-quantum-only key could not produce a QR code, even a multipart one, because its signatures are large enough to push the certificate past the old multipart ceiling. The QR capacity was raised, so a post-quantum key now shares as an animated multipart QR.

A truncated or incomplete message showed a raw range error that read like a crash; it now surfaces a clear "incomplete message" instead.

A key's primary could show a stale "Never" expiry next to a live subkey date. The primary expiry is now reconciled live from the key, and a key-server refresh no longer overwrites a real expiry with a removed one.

Sharing a key from a browser text selection, with page text around the armored block, now imports cleanly instead of erroring. CertainBot (#58).

The unlock-key dialogs now focus the passphrase field and raise the keyboard on their own. ltguillaume (#59).

The recipient picker shows the email under the name, so two keys with the same name are easy to tell apart.

Several Google Play stability reports from the September vitals review are addressed, including clipboard copy on some OEM ROMs and out-of-memory on very large picked files.

## Verify this build

Whole-file SHA-256, to confirm this download is the published file:

9842e68809d115bf15c7f1c9af67a0cdc941399c15ebc646175535fedbb3766e

Content hash, for rebuilders, which excludes the signature:

08f02c6be12da1e11f971ad64ec20400cb1cdf497a0114e69790068ba2f6600a

The APK is signed with the NorseHorse release key (A0CBC8F65AACE56F1C5B767753F9798E4919DE62), and PGPony's builds are reproducible: two independent clean builds of this release are byte-for-byte identical.
