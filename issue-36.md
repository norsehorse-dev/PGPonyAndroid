author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Status on the three parts: the biometric confirmation on key pair delete shipped in 4.2.0, released today. The recycle bin is on the 4.3.0 roster, designed together with per-key backup tracking so restore windows rest on real state. The Key Detail redesign is logged for 4.3.0's UI pass, decided in one sitting with the trust icons rather than piecemeal. I am on iOS next per my usual schedule, back on Android after.

NorseHorse
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
RC4 is up: https://pgpony.app/rc/4.3.0-RC-foss/PGPony-4.3.0-RC4-foss.apk (the .sha256 and .asc sit beside it).

Two things for you in this build.

Recycle bin (#36, part 1): deleting a key now soft-deletes it. Deleted keys go to Keys, then Recently Deleted, where you can restore them or purge them for good, and they auto-purge after 14 days. The delete sheet also shows whether the key is in a backup, so you know what you are about to lose before you confirm.

Zip result-sheet layout (#31, from your RC3 retest): you flagged that the Wrap in .zip toggle looked like it governed the .eml. The Bundle result sheet is now split into a Send as email block and a Send as file block, with the toggle under the file block, so it plainly wraps the .asc and leaves the .eml alone.

Retest: for the recycle bin, delete a key, confirm it lands in Recently Deleted, restore it, then delete another and purge it. For the layout, open a Bundle result and confirm the toggle reads as file-only.

This is the final feature RC for 4.3.0. The app is feature complete now; what remains is the test matrix and the release.

NorseHorse
--
author:	AraafRoyall
association:	none
edited:	false
status:	none
--
👌👌 thanks for the updates.


Here is some overview 

#  QR click lag 
Even QR now generating in bg the dialog appears after generating , looks like ui lag. The dialog should appear first then Show QR as Loading....

# Trust level image color

The last ultimate level option in trust level image should have green color ,all other should have diff color


# Sign as Optimization

We currently swiching sign switch then selecting key
We should need direct selector with a none option for not signed this will prevent or remove switch ,



--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Thanks, all three noted and headed for 4.4.0.

The QR dialog lag is a real one: the sheet waits for the image before it appears, so the tap feels dead. It should open right away showing "Loading" and fill in the QR when the background render is done. That is how it will work.

Sign-as: agreed, the toggle-then-pick flow is a step too many. It becomes one signing-key selector with a "None, don't sign" option, and the switch goes away.

On the trust colors, I want to get this right rather than quick. Ultimate is purple today and Verified is already green, so making Ultimate green would put two greens on the ladder and weaken the "higher means more trust" read. I am going to look at recoloring the whole ladder so the top still stands out without clashing. Open to what you had in mind for the green.

NorseHorse
--
author:	AraafRoyall
association:	none
edited:	false
status:	none
--
Good that you understood. 

Just swap that colors then one become green . 
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
All three are in RC3.

The QR sheet opens the moment you tap, showing a spinner, and fills in the code when the render finishes, so the tap no longer feels dead. Sign-as is one selector now with a "None, don't sign" option, and the separate switch is gone. On the trust colors, I moved green to the top: Ultimate is green now and Verified moved to blue, so there is a single green and it marks the highest trust. Ultimate keeps its star too, so it stands out on shape as well as color.

https://pgpony.app/rc/4.4.0-RC-foss/PGPony-4.4.0-RC3-foss.apk

Installs over your current build, no uninstall. To retest: open a QR on a large key and watch for the instant spinner, set sign-as to None and then to a key on the encrypt screen, and check the trust ladder on a key card and in Key Detail.

NorseHorse
--
author:	CertainBot
association:	contributor
edited:	true
status:	none
--
Hello, @AraafRoyall and @norsehorse-dev. I am not sure the new trust level colors are better or more intuitive than older layout. Reasoning:

Usually semaphore colors is the most intuitive way to identify trust level. Of course red is not necessary as user won't use malicious keys thus the neutral grey is a good choice for uncknown keys, gold for unverified and green for the trusted keys.

Expending green for my keys is unnecessary as I trust them anyway, so using the green as best level for public keys is what I expect for quick visual reference.

As said I already trust my private keys so marking them as ultimate, unless some is compromised, with a special color as the blue looked very intuitive to me.

I leave it here for discussion and do at your discretion. All other changes are very welcome.

Thanks
--
author:	CertainBot
association:	contributor
edited:	true
status:	none
--
And while we are on it, I would also suggest exchanging the X and ! shield symbols. 

X suits better the grey unknown shield where you don't really want to use the key in real life until some higher degree of trust. 

! symbol suits better the yellow shield denoting caution, a term which is even used in the explanatory text. Usually you want or need to use this key in real life but you still have to precede with caution as the identity is still not fully certain. I found the ! and yellow color being an excellent reminder in this case.

Thanks
--
author:	Umotas
association:	none
edited:	true
status:	none
--
Encrypted file has +30% size vs original size.
Does the app use --compression? (-zlib f.ex.)
(This file is not armor)

I use sq.exe in Windows, and the size of encrypted file <= the size of original file
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
@Umotas PGPony does compress. File encryption runs the data through ZLIB before encrypting, so a compressible file should come out smaller, not larger. Two exceptions: files above roughly 105 MB skip compression on purpose, since deflate over a large archive costs real time and saves almost nothing, and a file that is already compressed (JPEG, PNG, MP4, ZIP, PDF, most Office formats) can't be shrunk further by anyone.

The output itself is binary .gpg, not ASCII armor, so there's no base64 expansion inflating it.

On an already-compressed file, the +30% you're seeing would be OpenPGP's own per-message overhead: a public-key packet for each recipient, the integrity (SEIPD/MDC) data, and the packet headers. That is a fixed cost, so it looks large on a small file and negligible on a big one. sq carries the same overhead, so if its output came out smaller, the test file was compressible.

To tell which case this is, can you tell me the file type and rough size, and whether you used File mode or Text? If it was a compressible file under the size cutoff and we still came out bigger than the original, that's a real gap and I'd like a closer look, so the exact numbers or a sample I can reproduce with would help.

NorseHorse
--
author:	Umotas
association:	none
edited:	false
status:	none
--
Files:
<img width="448" height="195" alt="Image" src="https://github.com/user-attachments/assets/395105e6-fd88-425d-a9a2-388effba934d" />
SQ:
<img width="271" height="70" alt="Image" src="https://github.com/user-attachments/assets/40315b89-3194-479b-85a2-a8ce8068cae5" />
File was encrypted by PGPony:
<img width="724" height="273" alt="Image" src="https://github.com/user-attachments/assets/63dc640d-501d-4cce-8833-83508ffca45f" />
File was encrypted by SQ:
<img width="720" height="398" alt="Image" src="https://github.com/user-attachments/assets/fbfd4e90-cd14-402d-85cf-4e0469eb7444" />
my BAT-file for ENCRYPT by SQ:
<img width="627" height="113" alt="Image" src="https://github.com/user-attachments/assets/a05d9b89-c536-4d25-a92a-915053da4798" />
--
author:	Umotas
association:	none
edited:	false
status:	none
--
Check PLS:
<img width="270" height="573" alt="Image" src="https://github.com/user-attachments/assets/8f636247-2c58-4a6d-95c0-73a724ecbb8c" />
I try to encrypt by this keys:
ML-KEM-768 v6 - OK
ML-KEM-1024 v6 - OK
ML-DSA-65 v6 - I have this screen. But If I include 2 keys as Recipients (ML-DSA-65 v6 + ML-KEM-768 v6) - I have no problem.
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Two separate things here, both real, and both worth fixing. Thanks for the detail on each.

On file size: your packet dumps pinned it, and it isn't compression. PGPony compresses the file to essentially the same size sq does. The difference is the AEAD chunk size. A SEIPD v2 / OCB container splits the data into chunks and appends a 16-byte authentication tag to each one. sq uses 4096-byte chunks, so those tags cost about 0.4%. PGPony is writing 64-byte chunks, so it adds a tag every 64 bytes, about 25% overhead. On your APK that's roughly 3.2 MB of tags, the whole gap between our 16,299 KB and sq's 13,089 KB. It only shows on v6 (post-quantum) encryption, since that's the path that uses the AEAD container. The fix is to write a normal chunk size like sq's, which drops the overhead to a fraction of a percent.

On encrypting to an ML-DSA-65 key: that key isn't signing-only, it carries an ML-KEM-768 encryption subkey, so encrypting to it should work. The failure is on our side. PGPony can't yet read a composite ML-DSA key when it's used as a recipient, so the key gets dropped before its encryption subkey is reached, and you land on the misleading "No recipients and no password" error. One thing worth knowing: when you added ML-KEM-768 alongside it and it succeeded, it encrypted to the ML-KEM-768 key only, not to the ML-DSA-65 key, so that success is hiding the same gap rather than working around it. The ML-KEM-768 and ML-KEM-1024 keys work because they can be read directly; the composite ML-DSA primary is the part we can't read yet. We'll make a composite ML-DSA key usable as a recipient through its encryption subkey, and replace that error with one that says what actually happened.

Thanks for testing each key type separately and sending the dumps.

NorseHorse
--
author:	Umotas
association:	none
edited:	false
status:	none
--
I have a question. 
Why are you generating the key using the old "pre-quantum" algorithm?
<img width="626" height="394" alt="Image" src="https://github.com/user-attachments/assets/7c2f03b3-c85c-42e9-afe4-f761e40e13f7" />
I read this in manuals: "confidentiality is not post-quantum secure when encrypting to different keys unless all keys support PQ(/T) encryption schemes"
Maybe is this 'PQC-ready + backward compatibility'?
I think PGPony must generate or clear-post-quantum or compatibility-key.
What is your opinion.
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Good eye, and you're right to question it. That key has two encryption subkeys: the ML-KEM-768+X25519 composite, which is post-quantum, and a separate plain X25519 one, which is classical.

Here's the thing worth knowing. The composite subkey is already hybrid: it combines ML-KEM with X25519 in a single subkey, secure if either half holds. So on its own it gives you both post-quantum security and a classical safety net. The separate plain X25519 subkey doesn't add to that. Its only job is to let a tool that can't handle the composite algorithm still encrypt to the key.

And you've spotted its real cost. A sender that encrypts to every encryption subkey, which is what sq did in your earlier dump when it wrapped the session key to both subkeys, ends up protecting the message with the breakable X25519. At that point the message isn't post-quantum confidential, even though the PQ subkey is right there. So for a key whose whole point is post-quantum confidentiality, that classical subkey is a downgrade path, exactly the property your quoted caveat describes, happening inside one key rather than across recipients.

The fix is to make it a choice, and I'm planning it for 4.5.0: a post-quantum-only key option, the composite ML-KEM subkey with no standalone classical encryption subkey, so nothing can downgrade it. The tradeoff is that only post-quantum-capable tools can encrypt to it, which is the honest cost of guaranteed PQ confidentiality. The current key stays available as a clearly labeled compatibility option for people who still need to receive from classical-only tools.

Thanks for the inspect output, it made the issue concrete.

NorseHorse
--
