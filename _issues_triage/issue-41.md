author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
Thank you, this is a real bug and your report isolated it precisely. The clue that the same key imports from a file but not from the keyserver is exactly what points at the cause.

Here is what is happening. A key served over WKD arrives in binary form, and PGPony re-wraps it in ASCII armor itself before importing. That hand-written re-wrap is where it fails for some keys, which is why a file import of the same key works: the file path uses a different, more robust reader that handles the key directly. Kleopatra reads the WKD binary directly too, so it never hits this. Your key is fine; our re-wrap is not. This affects PGPony for Desktop for the same reason, and both will be fixed together.

The fix is to stop re-wrapping and hand the downloaded key straight to the reader that already works for files. It is scheduled for the 4.3.0 release. In the meantime the workaround you found, exporting the key to a file and importing that, produces exactly the same result with no downside.

NorseHorse
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
RC1 for 4.3.0 is up with this fix, if you are willing to retest on the key
that failed:

https://pgpony.app/rc/4.3.0-RC-foss/PGPony-4.3.0-RC1-foss.apk

The detached signature (.asc) and the sha256 sit beside it in the same
directory. Verifying them is optional; the README has a "Verify a release"
section if you want to.

What changed on your end: PGPony no longer re-wraps the WKD key itself. The
bytes it downloads now go straight to the same reader the file-import path
uses, which is the path that already worked for you. So the WKD
search-and-import you tried before should now behave the way the file
import did.

The retest that helps most: install this build, search for your key over
WKD the same way as before, and import it. If it lands without the
"Couldn't parse key" error, that is the confirmation I am after.

It installs in place over your current copy, including an F-Droid one, with
no uninstall and no data loss, since it is signed with the same key F-Droid
distributes for the reproducible build.

One note: this build is Android only. The same bug is in PGPony for Desktop
for the same reason and is fixed there in the next desktop release, so a
Desktop retest will still fail until that ships. I did not want you testing
Desktop and thinking it had regressed.

Thanks again for spotting that the same key imports from a file but not
from WKD. That comparison is what located the cause.

NorseHorse
--
author:	CertainBot
association:	contributor
edited:	false
status:	none
--
I have found a somewhat similar problem, not a bug though just a "missing feature". When I save a signed plain text message as a file.asc, the only method I have found to check the signature is to open the file in an editor, copy the text, and then paste and verify the signature. The file decrypt tool returns an error because the file isn't encrypted and the verfication tool needs a file for verification and another file with the signature.

In sum, would be interesting to have a way to add the file, extract the text and check the signature without the need of an external editor.

Thanks
--
author:	norsehorse-dev
association:	owner
edited:	false
status:	none
--
@CertainBot RC3 handles the signed-only file you described. Picking a .asc that is a signed but not encrypted message in the Decrypt file slot now verifies it in place: it reads the text and checks the signature against your keys and shows the result, instead of the "not encrypted" error or making you supply a separate signature file. No external editor.

https://pgpony.app/rc/4.3.0-RC-foss/PGPony-4.3.0-RC3-foss.apk

The .asc and sha256 are beside it; it installs in place over your current copy, F-Droid included, with no uninstall or data loss (same reproducible-build key).

Retest: save a signed plain text message as a .asc the way you did, then open it in the Decrypt tab. You should see the text and a signature result, green if my signing key is in your ring or a yellow unknown-signer if not, with no editor step. One scope note: this covers the cleartext-signed form, which is what saving signed plain text produces. If your file is an inline-signed message instead and does not verify, say so and I will add that path.



NorseHorse
--
author:	CertainBot
association:	contributor
edited:	false
status:	none
--
@norsehorse-dev thanks for the prompt fix. I tested the clear text signed message in a .asc file and works exactly as you described. Haven't been able to test the inline-signed message yet but so far the functionality looks perfect to me! Thank you. 
--

