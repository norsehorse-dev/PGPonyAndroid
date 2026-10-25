# PGPony Android 4.7.2: Planning

Status: open (Oct 24 2026). A point release on main after 4.7.1 (versionCode 472): the keyboard staying up on
Encrypt and Decrypt (user email, Oct 24), and the Play crash moved out of 4.7.1. RC1 built and checked on device
Oct 24; RC2 adds item 3, found while testing RC1. RC3 adds items 4 and 5 from the tester's RC2 report (Oct 24). If 4.7.2
follows 4.7.1 within days, Play gets 4.7.2 directly instead of 4.7.1.


## 1. The keyboard stays up after leaving a text field

**Status:** code in (Oct 24).

Origin: user email (Oct 24, on 4.7.1). On Encrypt, typing a message and then tapping the recipient picker, a
switch or a button leaves the keyboard over the lower half of the screen; the user has to close it by hand to
reach the options and the output. Compose keeps text focus when a non-text element is tapped, and no PGPony
screen cleared it.

Work: ui/util/KeyboardDismiss.kt. dismissKeyboardOnTap() on the Encrypt and Decrypt content and the recipient
picker sheet watches taps in the Initial pass (consuming nothing, so every control works as before); a tap (one
finger, no movement past the touch slop) outside every text field marked keepsKeyboard() clears focus and hides
the keyboard. Scrolling never closes it. All 18 text fields in ui/encrypt/Screens.kt carry keepsKeyboard(), so
tapping from one field to another does not flicker. No new strings. Test: KeyboardDismissTest (the hit test).

On device: Encrypt, type a message, tap the recipient card, a switch, the Encrypt button and empty space: the
keyboard closes each time and the control still acts. Tap from the message field to the password field: no
flicker. Scroll while typing: the keyboard stays. Same on Decrypt (input, passphrase) and inside the recipient
picker (search field, then a row).

Left out: other screens with text fields (Settings, Key Details sheets, Import, Pair) keep today's behavior;
they go in 4.8.0 once this one has been used.


## 2. Play crash: IllegalArgumentException in LayoutNodeSubcompositionsState

**Status:** code in (Oct 24), guard only.

Origin: Play Console, two clusters on 4.6.4, one user (3 and 5 events). Traces (Oct 24): both thrown from
LazyLayoutMeasureScope.measure inside a LazyColumn while scrolling (a fling and a drag). That is Compose's
duplicate-key check. The list is under fillMaxWidth().heightIn(max), which matches the recipient picker
(Screens.kt, keyed by fingerprint) and the Sign as sheet (SignAsSheet.kt, keyed by fingerprint); the contact link
sheet has the same shape but its contacts are merged by contact id. pgp_keys has no unique index on fingerprint,
so two rows with one fingerprint put the same key in the list twice.

Work: both lists drop a repeated fingerprint before keying (distinctBy). No new strings.

Left out (4.8.0): how two rows came to share a fingerprint, and a cleanup that merges them plus a unique index,
so the keyring itself holds one row per key.


## 3. Encrypt and Decrypt do not scroll while the keyboard is up

**Status:** code in (Oct 24), RC2.

Origin: found on device while checking RC1 (item 1's scroll test). With the keyboard open, the Encrypt screen does
not scroll, so the options and the Encrypt button under the keyboard cannot be reached without closing it first.
Not caused by item 1 (its tap detection consumes nothing). MainActivity calls enableEdgeToEdge(), so the window
never resizes for the keyboard, and unlike the sheets and the Keyring and Import screens, the Encrypt and Decrypt
content never applied the IME insets. The scroll area stayed full height with the keyboard drawn over it.

Work: the Encrypt and Decrypt content columns take consumeWindowInsets(padding) then imePadding() before
verticalScroll, so the scroll area ends at the top of the keyboard. consumeWindowInsets keeps the tab bar and
navigation bar space the Scaffolds already reserve from being counted twice. No new strings.

On device: Encrypt and Decrypt, focus the message field, then scroll to the bottom with the keyboard up: every
option and the Encrypt (Decrypt) button is reachable, with no gap between the content and the keyboard. Close the
keyboard: the screen returns to full height with no leftover space.

## 4. The passphrase dialog names the key without its email

**Status:** code in (Oct 24), RC3.

Origin: tester report on RC2 (Oct 24). Signing while encrypting, the Passphrase Required dialog shows the key's
name and short fingerprint but not its email, so a user with several keys under one name cannot tell from the
dialog which one is being unlocked. The dialog fell back to the email only when the key had no name.

Work: SignPassphraseDialog and DecryptPassphraseDialog (ui/encrypt/Screens.kt) show the email on its own line
under the name when the key has both, the same identity the key pickers show since 4.7.0. No new strings.

On device: encrypt and sign with a passphrase-protected key that has a name and an email: the dialog shows name,
email, short fingerprint. Same on Decrypt when the passphrase is asked for.


## 5. Decrypt fails when an email signature is pasted with the message

**Status:** code in (Oct 24), RC3.

Origin: tester report on RC2 (Oct 24). A paste that included an email signature as well as the PGP MESSAGE block
failed with a malformed message; the same message pasted marker to marker decrypted. The paste went to Bouncy
Castle's armor reader whole. Before the BEGIN line, that reader skips text only until a line that starts with a
dash, and takes that line as the armor header; a signature's row of dashes (or the "-- " separator) then became
the header and the next line an invalid armor header ("the armor could not be read").

Work: ArmorExtractor.messageOnly (crypto/ArmorExtractor.kt, already used for key import since 4.5.0) returns
the first complete PGP MESSAGE block and drops everything around it. effectiveDecryptInput applies it after the
MIME envelope unwrap, so the decrypt, the card and hidden-recipient detection and the composite inline check all
read only the block. Input with no complete block, or where the block is the whole input, passes through
unchanged, so an incomplete paste still reports as incomplete and an ordinary message reaches Bouncy Castle byte
for byte as before. No new strings. Test: ArmorExtractorTest (signature above and below, the "-- " separator,
no END line, no block, two messages).

On device: paste a message with a signature of dashes above it, then below it: both decrypt. Paste only the top
half of a message: still reported as incomplete.

Left out: clear-signed text and file decrypt keep their own parsing; check them for the same case in 4.8.0. iOS:
check both items against 8.4.0.


## Release

versionCode 472, versionName 4.7.2. Changelog 472.txt and RELEASE_NOTES_4.7.2.md after RC3 is checked. Same
release path as 4.7.1.
