A few things from this thread are in 4.5.0-RC5.

@AraafRoyall, the global switch you asked for is in. Settings > Security has a "Protect destructive actions" toggle, on by default. With it on, deleting a key, removing a subkey, and clearing all data all ask for your device authentication first. Turn it off and those actions keep their confirm dialogs but skip the prompt. On the trust colors: you and @CertainBot want opposite things there (you want green at the top for Ultimate, CertainBot wants green for verified public keys with blue for Ultimate), so I have left the ladder as it is for now rather than pick a side mid-thread. Same for the X and ! shield swap CertainBot raised. Both are still open, and I would rather settle them than flip them across builds.

@CertainBot, the delete dialog now has a "Revoke this key instead" button on key pairs. It opens the revoke flow so you can generate a revocation certificate before the key is gone, which is the case you made: there is no way to make one after a delete.

@Umotas, the ML-KEM-1024+X448 decrypt you hit on RC3 is not fixed with certainty yet. RC5 carries the imported-composite decrypt work, but my own sq build is not post-quantum, so I could not reproduce the 1024+X448 case locally the way you can. If you retest that exact round trip on RC5 (import the 1024+X448 key, then decrypt a file made for it) and it still fails, that pins it as a real gap specific to that key shape and I will chase it from there.

https://pgpony.app/rc/4.5.0-RC-foss/PGPony-4.5.0-RC5-foss.apk

Installs over your current build, no uninstall.

NorseHorse
