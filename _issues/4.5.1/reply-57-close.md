@WundreLust the multi-recipient fix is in 4.5.0, now public on Google Play and F-Droid. A message encrypted to your composite ML-KEM key alongside other recipients now tries every recipient slot on decrypt, so it opens for you whatever position your key sits in.

Closing this out. If you still hit a decryption failure on the release build with your two-key setup, reopen with the message and I will dig back in.

NorseHorse
