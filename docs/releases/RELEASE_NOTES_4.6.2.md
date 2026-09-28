# PGPony 4.6.2

Three new languages, Simplified Chinese, Ukrainian and Turkish, and the parts of the app that stayed in English whatever language you chose are now translated too. 4.6.2 carries versionCode 462 and installs in place over 4.6.1.

## New languages

Simplified Chinese (简体中文), Ukrainian (Українська) and Turkish (Türkçe) are now in the language list in
Settings and in Android's per-app language settings. A phone already set to one of them switches to it on its
own.

These translations are mostly machine-made. About a third of the Chinese strings reuse the wording of PGPony for
iOS, which a Chinese-speaking tester translated, so both apps use the same terms for keys, signatures and
passphrases. The rest of the Chinese, and all of the Ukrainian and Turkish, is machine translation. I checked
every string for placeholders and plural forms, but I don't read these languages, so some wording will be wrong
or stiff. Corrections are welcome in the PGPony-Translations repository on GitHub
(github.com/norsehorse-dev/PGPony-Translations) or by email to NorseHorse@norsehor.se.

Phones set to Traditional Chinese (Taiwan, Hong Kong, Macau) stay in English rather than getting Simplified
text.

## Korean

A volunteer is translating Korean. This release adds the strings finished so far, about 180 more, for roughly 650
of the app's strings. Korean is still not in the language list because much of the app is untranslated; a phone
set to Korean already uses what is there and English for the rest.

## Text that stayed in English

Some text was written straight into the code instead of the translation files, so every language showed it
in English: about 80 labels, buttons and messages (the empty Keyring, the key access recovery dialog, parts of
Exchange, Contacts, the hardware key screens and backup), and about 360 error messages from the encryption,
hardware key, key store, backup and mail app code. All of it now comes from the translation files, in every
language. Error messages are translated where they are shown, so the encryption code that raises them is
unchanged, and a message from a library PGPony has no translation for still appears as it is.

German, Spanish, French, Japanese, Portuguese (Brazil) and Russian also gain the 11 or 12 strings each was
missing, among them the "Allow expired keys" setting, the expired key warnings and the question about restoring
settings from a backup.

## Smaller fixes

- An error that read "Decryption failed: Decryption failed: ..." now names the failure once. The same goes for
  encryption, signing and import errors.
- Counts use real plural forms (keys found or linked, recipients, extra keys in an import), which matters in
  languages with more than two forms.
- Dates on Key Details and the card screen use your language's date format, and file sizes use your phone's
  number format.
- Key Details shows the trust level in your language.
- On Android 8 to 12, error messages follow the language chosen in PGPony rather than the phone's language.

## A build check for translations

Every build now compares the format arguments (%1$s, %2$d) of each translated string with the English one, and
checks that plurals carry every form their language needs. A mismatch stops the build, so a translation mistake
can no longer reach the app as a crash. The check only reads the string files and does not change the APK.

## Verify this build

Whole-file SHA-256 (is this download the published file):

```
856ab53741eac9154474a5e4ea8c728b82d4f4652d468f4ce5a083fc7b3cc743
```

Content hash (for rebuilders; excludes signature, see docs/REPRODUCIBLE_BUILDS_PLAYBOOK.md):

```
6c94aa270a854d6344d6fca678142969aa3015e914862efc271041254109ea25
```

The APK is signed with the NorseHorse release key
(A0CBC8F65AACE56F1C5B767753F9798E4919DE62); the detached signature is attached to
this release.
