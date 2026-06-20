## Keyring screen — auto-hiding "+" FAB

**User-visible**
- The purple "+" (add key) button on the Keyring tab now fades out after a
  short idle period (2.5s) instead of staying on screen permanently.
- It fades back in (≈250ms alpha fade) on any tap anywhere on the Keyring
  screen, or on scrolling the key list in either direction. Each reveal
  resets the idle timer, so it hides again once interaction stops.
- While hidden it no longer blocks the list beneath it: a tap in that corner
  reveals the button rather than triggering add-key. Add-key (and the
  generate / import / hardware-key menu) only fires when the button is
  already visible.

**Android impl**
- `FAB_IDLE_TIMEOUT_MS = 2500L` and `FAB_FADE_MS = 250` are single tunable
  top-level constants in `KeyringScreen.kt`.
- Visibility is driven by `fabShown` + `animateFloatAsState` (tween
  `FAB_FADE_MS`) → `Modifier.alpha(fabAlpha)`. The FAB menu is only composed
  while `fabShown || fabAlpha > 0f`; at alpha 0 it is absent from the tree, so
  it cannot catch touches or block the list.
- A `LaunchedEffect(lastFabInteraction, fabExpanded)` restarts the idle
  countdown on each interaction and sets `fabShown = false` after the timeout.
  It returns early while `fabExpanded` is true so the open add-menu never
  auto-hides.
- Reveal sources: (1) taps — a `pointerInput` on the content `Box` observes
  pointer-down on `PointerEventPass.Initial` and bumps `lastFabInteraction`
  without consuming the event, so `KeyCard` clicks still work; (2) scroll — a
  `snapshotFlow` over `(isScrollInProgress, firstVisibleItemIndex,
  firstVisibleItemScrollOffset)` inside the `PullToRefreshBox` bumps on any
  scroll change.
- The main FAB captures `fabShown` BEFORE bumping; a tap while hidden (mid
  fade-out) only reveals, while a tap while visible toggles the add menu.
- The `expanded` local was hoisted to a screen-level `fabExpanded` so the
  auto-hide effect can read it. No behavior of the generate / import /
  hardware-key actions changed.

**iOS port notes**
- No direct port required. The iOS Keyring (`KeyringListView`) uses a
  persistent navigation-bar "+" button, not a floating action button, so
  there is no always-on FAB to auto-hide. This is an Android-Material-specific
  affordance.
- If an equivalent is ever wanted on iOS, it would be a floating overlay
  button with the same idle-timer logic (a `Timer`/`Task` reset on
  `simultaneousGesture` taps and `ScrollView` offset changes), gated so the
  hidden state doesn't intercept touches.

**Files touched**
- `app/src/main/java/com/pgpony/android/ui/keyring/KeyringScreen.kt`
  (iOS counterpart: `KeyringListView.swift` — no change; add button is a
  toolbar item, not a FAB).
