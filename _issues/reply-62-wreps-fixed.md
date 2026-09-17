@wreps8Owt fixed in 4.5.0-RC9.

A nistp521 public point is 0x04 || X || Y = 133 bytes, and the code building the Cipher DO for PSO:DECIPHER was writing that length as a single short-form byte, which only reaches 127. P-256 and P-384 points are 65 and 97 bytes so they slid under the limit, nistp521 is the first curve that crosses it. OpenKeychain writes the length in long form, which is why it worked there. It now uses long-form BER lengths, so 133 encodes as 81 85.

There was a second bug sitting right behind that one that would have hit you next. The RFC 6637 KDF had the Curve25519 OID hardcoded into its param, so even with the TLV fixed a P-521 key would have derived the wrong key-encryption key and failed at unwrap. It now reads the real curve OID off your key.

https://pgpony.app/rc/4.5.0-RC-foss/PGPony-4.5.0-RC9-foss.apk

I do not have a nistp521 SmartPGP card here, so I could only lock the byte-level encoding in unit tests. If you install this over your current build and run the same decrypt, that confirms the card round-trip end to end. Let me know how it goes either way.

NorseHorse
