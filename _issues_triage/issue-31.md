author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Before scoping this I want the underlying need, because the answer changes what gets built: several files as one unit (Bundle mode may already be it), a transport that mangles .asc extensions, or something else? It is logged on the 4.3.0 roster pending your answer. I am on iOS next per my usual schedule, back on Android after.

NorseHorse
--
author:	AraafRoyall
association:	none
edited:	false
status:	none
--
I mean , we need zip formate later or encrypted asc into the zip for various reasons
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
That is what is committed for 4.3.0: the encrypted output (.asc or .gpg) packaged inside a .zip as an output option, and decrypt accepting a .zip with the encrypted file inside it directly. One note so expectations stay right: the zip layer is packaging, the protection is still the encryption inside it.

NorseHorse
--
author:	AraafRoyall
association:	none
edited:	false
status:	none
--
Exactly. 👌👌👌👌👌
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
RC3 for 4.3.0 is up, and it carries four of your open ones. If you are up for retesting:

https://pgpony.app/rc/4.3.0-RC-foss/PGPony-4.3.0-RC3-foss.apk

The .asc signature and the sha256 sit beside it. It installs in place over your current copy, including an F-Droid one, with no uninstall and no data loss, since it is signed with the same key F-Droid distributes for the reproducible build.

#31, zip. Encrypt has a wrap-in-zip option on the file and bundle results now, and decrypt takes a .zip with the encrypted file inside and unwraps it for you. The zip is packaging, the protection is still the encryption inside. One heads-up on the Bundle result: the Wrap in .zip toggle governs the encrypted .asc, not the Share as Email path, since the .eml is left as a real email for mail clients. Its spot right under the email button makes that look backwards, and I am regrouping that sheet in the next build so the toggle clearly belongs to the file actions. Retest: turn on Wrap in .zip, share or save the .asc, and decrypt that .zip back.

#24, trust marks. All four decided together so shape and color climb with rank: shields with the mark inside for unknown, unverified and verified (question, exclamation, check), and a star on the shield for ultimate. The key card and the contacts list read from one source now, so they cannot drift apart. Retest: look at keys at different trust levels and tell me the ladder reads right.

#36, the Key Detail redesign. The long scroll is gone. The actions live in a menu off the top bar, and Share Public Key sits beside the fingerprint. The recycle bin half of this issue is still coming in a later 4.3.0 build, so this covers the redesign only. Retest: open a key and check the actions are where you expect.

#22, sign key. The picker now lets you choose which signing subkey signs when a key has more than one, inside the same Sign as sheet. A key with a single signing key shows no extra choice. Retest: with a key that has more than one signing subkey, pick one and sign.

NorseHorse
--

