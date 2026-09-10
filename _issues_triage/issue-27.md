author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
K-9 rejects v5 and v6 keys at import, so the limitation is on their side, but 4.2.0's signing defaults and fallback keys (released today) are built for exactly this situation: set a classical signing default and fallback on your key in Key Detail. Please try that setup and report back. The provider surface is the leading candidate for 4.3.0's theme. Following my usual schedule I am on iOS for now and back on Android when that wraps.

NorseHorse
--
author:	bluemle
association:	none
edited:	false
status:	none
--
Thanks a lot! Encryption and decryption works  now in K9 mail. I tried with version 4.2.0 and v6 ML-KEM-1024 keys.

There was one more issue I found when using K9 mail with a multiple identity key:
When I try to send an email in K9 to the recipient address which is not the primary identity of a key, it seems to not find the key, at least it won't offer me the option to encrypt the email.

It works again once I create a new key with the recipient email address as the primary ID.

For all my tests I used v6 ML-KEM-1024 keys.

--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Good to hear the v6 ML-KEM-1024 round trip works in K-9 now, and thank you for the second finding. It is a real bug, and your repro pinned it exactly.

The app resolves a recipient address to a key by the key's primary identity only. The extra identities you add are stored, but they are not searchable the way an incoming mail address is matched, so a message addressed to a secondary identity finds no key and the encrypt option never appears. Making that address the primary is the workaround you already found; it should not be necessary.

I am fixing this in a 4.2.1 point release rather than waiting for the next feature version, since it breaks the whole reason to have a second identity. I will post here when the build is up.

NorseHorse
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Fixed, and I would like you to confirm it before I release it, since your setup is exactly where the bug lives. A release candidate is up:

https://pgpony.app/rc/4.2.1-RC-foss/PGPony-4.2.1-RC1-foss.apk

Signature and checksum are beside it. It reports as 4.2.1 in Settings, About, and installs over 4.2.0 in place.

The app was matching a recipient address against a key's primary identity only, so a message addressed to a secondary identity found no key and the encrypt option never appeared. It now matches any identity on the key, in every place the mail provider resolves an address.

When you have a moment: with your multi-identity v6 ML-KEM-1024 key, send from K-9 to the secondary identity address that failed before, and confirm the encrypt option appears and the message goes through. If it does, I will cut the final. If anything is still off, I would rather hear it now.

NorseHorse
--
author:	bluemle
association:	none
edited:	false
status:	none
--
Thanks a lot for the quick fix!
I just tried the same workflow and no issues anymore. Encryption appeared when sending email to secondary identity and decryption of the sent as well as of received message works flawlessly!
--

