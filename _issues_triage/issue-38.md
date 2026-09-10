author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Hi,

There was a reproducible build issue that blocked F-Droid updates after 4.0.4, see #28. It’s fixed on my end, and the update is now waiting on F-Droid’s build cycle. 4.2.0 only went out a few hours ago, so they haven’t even tried that one yet.

F-Droid pulls releases straight from this repo and rebuilds them itself. I don’t submit updates to them directly, so there’s nothing left for me to push. It should catch up on its own.

If you don’t want to wait, there’s a direct download at https://pgpony.app/apk. It’s signed with the same release key as the F-Droid build, so it installs right over an F-Droid install and F-Droid will update over it once it catches up.

NorseHorse
--
author:	EngineerGlitch
association:	none
edited:	true
status:	none
--
I'll try to add this in Obtainium :
https://pgpony.app/apk

Also thanks you for this great app, I was worry that their would be only OpenKeychain forever on Android for PGP, but thanks to you it's no longer the case.
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
That should work with Obtainium’s HTML source type. The download links are plain hrefs like /downloads/PGPony-4.2.0.apk, so the version comes straight off the filename. Let me know if the page layout gives it trouble and I’ll adjust the markup.

There’s also an email notification signup on that page if you want the hash and release notes as each version lands, optionally PGP-encrypted to your key.

Thanks for the kind words. OpenKeychain has carried Android alone for a long time, so having a second option seemed worth building.

NorseHorse
--
author:	EngineerGlitch
association:	none
edited:	true
status:	none
--
Yeah, Obtainium is working with : 
https://pgpony.app/apk

True, but since OpenKeychain is "discontinued", it's was good to have a more modern alternative.

Also very sad to see PGP not this used, I've got that idea back in the head to make SMS/MMS more secure by making some kind of PGP system on top (like your phone number and contacts tied to a PGP key so you can easily see encrypted SMS/MMS) so you don't have to trust encryption of others apps or protocols (this would also mean even without Internet, PGP would still works via SMS/MMS), but since I can't really code any apps (not really good at this), and things like Session and Signal exist, well this idea stay a idea.
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Good to hear Obtainium picked it up.

On the messaging idea, the closest thing I have is CarrierPony (https://carrierpony.com). It's OpenPGP messaging on the same crypto core as PGPony, no account and no phone number, and the relay in the middle only forwards sealed envelopes it can't read. That covers the part about not trusting someone else's protocol. It doesn't cover the part you actually care about, though, since it still needs a data connection.

Fair warning on it: it's a work in progress. The app source isn't open yet, though it will be, and it isn't on F-Droid yet either. The crypto core it runs on is already public under Apache-2.0. It works, but it's younger and less developed than PGPony, so judge it on that basis.

SMS/MMS as the transport is a real idea and nothing stops it technically. Binary PGP output in an MMS attachment carries a full message fine, and short texts fit in a few concatenated segments. The obstacles are platform ones. Google Play only grants SMS read permissions to an app that is the user's default SMS handler, so it has to be a whole SMS client rather than something that sits alongside your existing one. F-Droid has no such rule. iOS is worse: apps can't read incoming SMS at all, so an iPhone version could send but never receive.

Android-only, distributed outside Play, replacing your SMS app. That's the shape it would have to take. Not impossible, just a bigger thing than it sounds like.

NorseHorse
--
author:	EngineerGlitch
association:	none
edited:	true
status:	none
--
Yeah, for the client part, I knew that it would need to replace the SMS/MMS client, it technically also could be on Google Play not just third-party stores. Would be a great thing to see people sending each others E2EE over this really old protocol, the only question would be : Should it have some phone public PGP key discovery ? (Public key appear if you have the phone number in the contacts list for example).

Also I added PGPony to a [anonymity guide](https://t.me/s/electronicalwest/18) (FR/EN) I made, i'll check on the others software you made.
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
You're right about Play, my mistake. Default SMS handler is one of the permitted uses for those permissions, so it can ship there as long as it's the actual SMS app.

On key discovery, I'd avoid a phone-number directory. A server that maps numbers to keys has to be online, which kills the offline property that makes the idea interesting in the first place, and it can be enumerated to find out who uses the app. That's the same criticism people level at phone-number-based messengers.

The version that keeps the property: exchange keys in band. First contact sends your public key over the same SMS or MMS channel, the app pins the fingerprint on first sight, and both sides get a short comparison code they can check by voice or in person. After that your contacts list can show which numbers you already hold a key for, computed locally on the device with nothing queried and nothing uploaded. You get the contacts-list experience you described without a directory existing anywhere.

One thing to design around: SMS sender numbers are spoofable and SIM swaps happen, so a key change for a known number can never be silent. It has to be loud and require reconfirmation, the way SSH complains when a host key changes.

If you want an online lookup on top for people who have data, WKD and keys.openpgp.org already work that way and PGPony supports both. I also run keys.pgpony.app, which logs without IP addresses or query strings, so a lookup doesn't record who asked about whom. Either way, keep it opt-in and separate from the offline path.

Thanks for including it in the guide. Small correction if you edit it: the app is PGPony, not PonyPGP. The link is right.

NorseHorse
--
author:	EngineerGlitch
association:	none
edited:	false
status:	none
--
Thanks for the correction haha, I writted it a little time ago, and yes you are right, if one day I make the app, I don't really think for now since i'm not good at coding, and you're totally free to take the idea :) that would be better without some sort of discover that could be takeover, WKD and keys.openpgp.org are a better idea, voluntary and would require no infrastructure on my side.
--
author:	CertainBot
association:	contributor
edited:	false
status:	none
--
> Also very sad to see PGP not this used, I've got that idea back in the head to make SMS/MMS more secure by making some kind of PGP system on top (like your phone number and contacts tied to a PGP key so you can easily see encrypted SMS/MMS) so you don't have to trust encryption of others apps or protocols (this would also mean even without Internet, PGP would still works via SMS/MMS), but since I can't really code any apps (not really good at this), and things like Session and Signal exist, well this idea stay a idea.
>

PGP is actually widely used in the software industry. Every serious FOSS developer release his apps with his signature to avoid files being tampered with. It's the final user who usually doesn't pay much attention to the signature. 


--
author:	EngineerGlitch
association:	none
edited:	false
status:	none
--
> PGP is actually widely used in the software industry. Every serious FOSS developer release his apps with his signature to avoid files being tampered with. It's the final user who usually doesn't pay much attention to the signature.

I should have precised "not this used in communication".
--

