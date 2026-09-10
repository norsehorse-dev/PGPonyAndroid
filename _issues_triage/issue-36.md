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

