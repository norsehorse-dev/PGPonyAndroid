@Umotas yes, please do, that is exactly what would help. My own sq build is not post-quantum, so I cannot generate an ML-KEM-1024+X448 key or a file encrypted to one on my side, which is why this case is hard for me to reproduce directly.

What would let me reproduce it end to end:

- A throwaway ML-KEM-1024+X448 key pair generated in sq, secret key included. Make it a test key, not one you use for real, since you would be sending the private half.
- A small file encrypted in sq to that key that PGPony fails to decrypt.
- Your sq version and the exact commands you ran to generate the key and to encrypt the file.

With the key and the failing file in hand I can trace exactly where import or decrypt drops it and fix it against your real output instead of guessing. Attach them here, or send them to NorseHorse@norsehor.se, whichever you prefer.

NorseHorse
