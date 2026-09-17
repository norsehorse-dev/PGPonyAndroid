Fixed in RC8. Once I had your sq build and could encrypt a file to that 1024+X448 key myself, it broke right away and I could trace it.

It was not the crypto. Pasting the same message as text decrypted fine, opening it as a FILE did not. The file path streams the data, and the streaming decrypt never handed your imported composite key to the part that opens the ML-KEM subkey, so it reported no held composite secret key even though the key was right there. The file path now passes the composite key through the same way the text path already did, and there is a regression test built from your key and file so it stays fixed.

https://pgpony.app/rc/4.5.0-RC-foss/PGPony-4.5.0-RC8-foss.apk

Installs over your current build, no uninstall. Import your 1024+X448 key again and decrypt the file, that is the exact case this fixes.

NorseHorse
