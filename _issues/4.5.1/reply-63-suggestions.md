@CertainBot all three are in 4.5.1-RC2.

QR: the codes were shrinking because a density change I made in 4.5.0 pushed more data per frame while the renderer scaled up a low-resolution matrix, so the modules came out small inside a wide quiet zone. The multipart split is rebalanced and each frame now renders from its natural module resolution scaled by a clean integer factor, so the codes fill the space and every frame is the same size instead of the last one being larger.

Default Key: Settings > Keys & Servers > Default Key is a picker now. Tap it and choose any of your key pairs, rather than it just showing the current one.

Key Details shortcut: the header avatar is the button, the way you suggested. On a public key it takes you to Encrypt with that key preset as the recipient, on a key pair it takes you to Decrypt. There is a one-time hint the first time you open a key so it is discoverable without adding anything to the page or the menus. I went with the avatar over folding it into the recipient set, so it stays one clear action.

https://pgpony.app/rc/4.5.1-RC-foss/PGPony-4.5.1-RC2-foss.apk

Installs over your current build, no uninstall. Have a look and tell me if the QR sizing and the shortcut feel right.

NorseHorse
