# PGPony Android 4.7.2: Planning

Status: open (Oct 24 2026). A point release on main after 4.7.1 (versionCode 472): the keyboard staying up on
Encrypt and Decrypt (user email, Oct 24), and the Play crash moved out of 4.7.1. One RC, then release. If 4.7.2
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


## Release

versionCode 472, versionName 4.7.2. Changelog 472.txt and RELEASE_NOTES_4.7.2.md after RC1 is checked. Same
release path as 4.7.1.
