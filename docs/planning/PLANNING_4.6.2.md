# PGPony Android 4.6.2: Planning

Status: open (Sep 27 2026). A translations-only release: Simplified Chinese, Ukrainian and Turkish as new
languages, plus the Korean translation's progress so far. No code changes beyond registering the languages, so
the diff from 4.6.1 (the reviewed baseline) stays easy to read.

versionCode 462. Branch: `4.6.x`, cut from the v4.6.1 tag, not from main. Main already carries 4.7.0 work
(KeyValueSettings, the Add Subkey lifetime change and others), and none of that ships in 4.6.2. The language
commits are cherry-picked onto main afterwards so 4.7.0 keeps them.

Versioning note: while the external review is pending, releases stay on 0.0.1 steps where possible. versionCodes
follow the patch number, so 4.6.9 (469) is the last before 4.7.0 (470) takes the next code.


## 1. Simplified Chinese (zh-Hans)

Moved here from 4.7.0 item 14. Origin: a user, by email, Sep 26 2026.

- Resource folder values-b+zh+Hans (the script qualifier covers zh-CN, zh-SG and other Simplified locales).
- Reuse the iOS zh-Hans strings wherever the Android string means the same thing, key terms first (encrypt,
  decrypt, sign, verify, key pair, subkey, fingerprint, keyring, trust levels, passphrase), so both platforms use
  the same words; machine-translate the rest.
- Plurals: Chinese uses only the "other" form.
- Check that CJK text renders in the fingerprint (monospace) and QR / Exchange views.
- Picker name: 简体中文.


## 2. Ukrainian (uk)

Origin: a user request, Sep 2026 (already answered).

- Resource folder values-uk. Machine translation, with Russian as a cross-check for terminology only; never
  copy Russian strings into Ukrainian.
- Plurals need all four forms Ukrainian uses: one, few, many, other. This is where machine translation most
  often goes wrong; check every <plurals> entry by hand against the CLDR rules.
- Picker name: Українська.


## 3. Turkish (tr)

Origin: NorseHorse, Sep 2026 (privacy-tool audience).

- Resource folder values-tr. Machine translation.
- Plurals: one and other.
- Turkish dotted and dotless i: any case change on text must not use the Turkish locale by accident. Kotlin's
  uppercase() and lowercase() use the invariant locale, which is correct; check there is no toUpperCase() /
  toLowerCase() without a locale and no Compose text transform that would turn "i" into "İ" in labels,
  fingerprints or file names.
- Picker name: Türkçe.


## 4. Korean progress (ko), not yet in the picker

A volunteer is translating Korean. values-ko already ships and Android uses it on any phone set to Korean, even
though Korean is not in locales_config or the in-app picker, so today Korean phones see a half-English app.

- Pull the strings the translator has finished so far from the translation repository into values-ko. Do not
  machine-fill the rest; that is the translator's work.
- Keep Korean out of locales_config and the picker until the translation is complete; enable it in a later
  0.0.1 release.


## Shared work for every new language

- Add the locale to res/xml/locales_config.xml (zh-Hans, uk, tr) and to i18n/LanguageManager with its native name.
- Keep every format argument (%1$s, %1$d), escape (\', \n) and XML entity intact. Run lint and a script that
  compares the format arguments of every translated string against values/, and fail the build on a mismatch.
- A string missing from a translation falls back to English; that is acceptable, a crash is not. Missing plural
  quantities for a locale's rules are not acceptable.
- Store text: fastlane/metadata/android/<locale>/ (title, short description, full description) for zh-CN, uk and
  tr, and the same in the Play listing. Changelogs stay English.
- Release notes and the reply to each requester say plainly that these translations are mostly machine-made and
  ask for corrections.
- Reviewers: ask the iOS zh-Hans translator and the Chinese requester to check the main screens (Encrypt, Decrypt,
  Keyring, Key Detail, Settings, the share dialog) on an RC; the Ukrainian requester for Ukrainian.


## Release

- RC from the 4.6.x branch; reviewers check the RC; then the usual reproducibility gate on v4.6.2 and the
  release. F-Droid picks the tag up as usual.
- Changelog (462.txt) lists the new languages and says they are mostly machine translations.
- Cherry-pick the language commits onto main.
