Two things from this thread are in 4.5.1-RC2.

@AraafRoyall I added the switch you were after, as an opt-in rather than the default. Settings > Security has a new Hide destructive actions toggle, off by default. Turn it on and delete key, remove subkey, remove User ID, and clear all data disappear from the app entirely, so they are not there to hit at all. Revoke stays, since it is a safe action. It is also offered on the onboarding privacy screen so a new user can switch it on from the start. It sits alongside Protect destructive actions, which stays on by default and gates those same actions behind your device unlock for anyone who keeps them visible. So there are two independent choices now: keep them and gate them behind auth, or hide them completely. You get the second one.

@CertainBot the subkey remove dialog has Revoke this subkey instead now, matching the revoke-instead button on the key delete dialog, since a removed subkey cannot be revoked afterward either.

The trust colors and the X / ! shield swap are still open. I have not forgotten them, I would rather settle them than flip them across builds.

https://pgpony.app/rc/4.5.1-RC-foss/PGPony-4.5.1-RC2-foss.apk

Installs over your current build, no uninstall.

NorseHorse
