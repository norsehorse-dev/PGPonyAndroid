author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Every one of these is now in the 4.2.0 plan. I am answering all of them here rather than seven times over, purely to save time, so this covers #16 through #22.

#19, losing state with biometric lock. Real bug, and I found the cause. The lock screen returns early in the navigation host, which tears the whole navigation graph out and rebuilds it fresh on unlock, so it always lands back at the start. That is why you cannot add a password to the store with the lock on: it is a multi-step flow and every switch away throws the position out. Small fix. This is the one I most want in sooner rather than later.

#22, sign key selection. You are right, and it is narrower than it looks. The "Sign as" picker already exists and is wired into Text, File and Bundle. The Sign tab, the one screen whose entire job is signing, is the only place without it. Lifting the same component across is a small change. Your other suggestion, a default signing key separate from the encryption default, already exists inside that picker as "set as default", so that half is there once you can reach it.

#17, disabling the buttons on empty input. Correct. Text and Sign modes enable the button regardless of content; only File and Bundle check. Compose does it with a predicate rather than a text watcher, but the intent is right and it is a small change. Worth it beyond tidiness: pressing Encrypt on an empty field currently gives you an error, which teaches a new user that the button lies before it teaches them anything else.

#20, sections in Settings. Agreed, and overdue. That screen is a single file of about 72 KB rendering as one continuous list, and it is about to get worse: a passphrase timeout picker and hardware key session settings are both queued to land in it. Grouping needs to happen before those go in, not after.

#16, Verify as its own tab. Yes. Verify sits inside Decrypt as a button, which makes it look like a kind of decryption when it is a separate operation that happens not to need a private key. I would do it as a Verify mode alongside Text and File rather than a new top-level tab, so it mirrors Sign on the Encrypt side.

#21, confirmation before deleting a key. Good instinct, and deleting a secret key is the only irreversible destructive thing in the app. I want to do it properly rather than as three stacked prompts. The valuable part is not the biometric check, it is knowing whether the key has ever been backed up. "This key is in a backup from 12 June" and "this key has never been exported, deleting it destroys it permanently" are different messages and should not look the same. Three confirmations for a key someone just made by mistake only teaches people to click through warnings.

#18, the redesign. Splitting this one. The Sign half is #16 and I am doing it. The navigation half I am going to push back on, at least for now. Exchange is how someone finds a key when they do not already know where to get one, and moving it into an overflow menu because it is not needed by someone who does is how an app ends up usable only by people who already understand it. If more people say the same thing, or the install stats say it, I will revisit. Volume mounts is a much larger question that runs into a decision already settled the other way (the password store is deliberately read only on both platforms), so it needs that reopened before it can be scoped at all.

On timing, and I would rather be straight than optimistic. 4.1.0 goes out first. Then I owe the iOS side real work, hopefully no more than four to seven days. That does not block the small stuff here though: a few of these are contained enough that I can do them alongside the iOS work and ship them as a 4.1.1 patch rather than holding them for 4.2.0. The larger ones, Settings sections and the Verify tab, wait until I am back on Android properly.

You have found more in this app than anyone else, three rounds running, and the bundle work in 4.1.0 exists because you kept pushing on it. Thank you for that.
--
author:	AraafRoyall
association:	none
edited:	true
status:	none
--
**=============================**

#19 Todo ⏳

#22 Done ✔️

#17 Done ✔️

#20 ToDo ⏳

#16 ToDo ⏳

#21 ToDo ⏳

#18 Just move contact and Exchange options to Menu Bar Options of The Keyring tab 👌or should i show sample image ? 

And in place of them put Verify tab and Volumes mount in bottom bar. (Hope u understood).


Cool . Go for you iOs work, and i keep finding More features and bugs 
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Most of this shipped in 4.2.0: per-key signing defaults resolve which key signs, separately from the encryption recipient. What remains is a picker for multiple signing subkeys within one key, which is on the 4.3.0 roster now that subkey display exists to build on. Try the signing defaults in 4.2.0 and tell me what is still missing. I am on iOS next per my usual schedule, back on Android after.

NorseHorse
--

