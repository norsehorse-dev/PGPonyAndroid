# NorseHorse Android Update Log

> Tracks every UX/feature change shipped to the Android apps (PGPony,
> NeighCheck, EntityDesk) along with the porting notes needed to
> bring iOS to parity later. Append a new section under each app for
> every shipped update. Don't delete entries — old context becomes
> useful when iOS reviewers ask "what changed since last submission."

**Last revised:** 2026-05-14
**Apps covered:** PGPony, NeighCheck, EntityDesk (all Android Google
Play closed-testing builds)
**iOS port status overall:** Not started except where noted

---

## Summary table

| App        | # | Update                                  | Date       | Android | iOS port |
|------------|---|-----------------------------------------|------------|---------|----------|
| PGPony     | 1 | Haptic feedback pass                    | 2026-05-12 | Built   | Bundle ready, not deployed |
| PGPony     | 2 | Wire clipboardAutoClear setting         | TBD        | Planned | Not started |
| NeighCheck | 1 | Pull-to-refresh (Jobs + Shifts)         | 2026-05-12 | Built   | Not started |
| NeighCheck | 2 | Pull-to-refresh (Mileage + Calendar)    | 2026-05-12 | Built   | Not started |
| EntityDesk | 1 | "Updated X ago" row on entity cards     | 2026-05-12 | Built   | Not started |
| EntityDesk | 2 | Loading skeletons (Dashboard + Detail)  | 2026-05-12 | Built   | Not started |

---

## PGPony

### PGPony 1 — Haptic feedback pass

**Built:** 2026-05-12 · versionCode 2, versionName "1.0.1"

**User-visible behavior**
- Success haptic when a message encrypts
- Success haptic when a message decrypts (text and file results)
- Light tap haptic when copying any content to the clipboard
- Success haptic the instant a QR code is captured

**Android implementation**
- New helper `ui/util/Haptics.kt`: wraps `View.performHapticFeedback`
  with API-aware constants — `HapticFeedbackConstants.CONFIRM` on
  API ≥ 30, `VIRTUAL_KEY` fallback on 26-29; exposes `success()`,
  `tap()`, `reject()`.
- `EncryptDecryptViewModel` adds `events: SharedFlow<Event>` with
  `EncryptSuccess` and `DecryptSuccess`. Emitted from the success
  paths. Replay = 0 so late subscribers don't refire past events.
- Screens collect via `LaunchedEffect(Unit) { viewModel.events
  .collect { ... haptics.success() } }`.
- Copy buttons fire `haptics.tap()` directly on `onClick`.
- QR scanner fires `haptics.success()` in `onQRDetected` before
  navigating away.

**iOS port notes — partially pre-built**
A SwiftUI port was bundled earlier as `PGPony_haptic_pass.zip` but
not deployed (the upload was misrouted to iOS before we realized
closed testing is Android-only). When the iOS App Store unblocks
PGPony v4.0, that bundle is the starting point.

- `AppState.copyToClipboard()` → add
  `UIImpactFeedbackGenerator(style: .light).impactOccurred()`
- `EncryptionResultView`, `FileDecryptionResultView`,
  `DecryptionResultView` → `.sensoryFeedback(.success, trigger:
  didAppear)` with `@State var didAppear = false` flipped on appear.
  Requires iOS 17+, project is on 17.6+ so fine.
- QR scanner — iOS already has `UINotificationFeedbackGenerator()
  .notificationOccurred(.success)` at `ExchangeView.swift:811-812`.
  No change needed.

The Compose `SharedFlow` / `LaunchedEffect` pattern doesn't transfer.
SwiftUI's `.sensoryFeedback(trigger:)` is cleaner — fires once when
the trigger value changes.

**Files touched (Android)**
- NEW: `app/src/main/java/com/pgpony/android/ui/util/Haptics.kt`
- MOD: `app/src/main/java/com/pgpony/android/ui/encrypt/EncryptDecryptViewModel.kt`
- MOD: `app/src/main/java/com/pgpony/android/ui/encrypt/Screens.kt`
- MOD: `app/src/main/java/com/pgpony/android/ui/exchange/ExchangeScreen.kt`
- MOD: `app/src/main/java/com/pgpony/android/ui/scanner/QRScannerScreen.kt`

**iOS counterpart files (when porting)**
- MOD: `App/AppState.swift`
- MOD: `Views/Encrypt/EncryptionResultView.swift`
- MOD: `Views/Decrypt/DecryptView.swift`

---

### PGPony 2 — Wire clipboardAutoClear setting (PLANNED)

**Status:** Planned. Targeted for the next off day.

**Why this is on the list**
The Settings screen already exposes a toggle + interval picker
(30s/1m/2m/5m) for clipboard auto-clear, and `SettingsViewModel`
persists both. But the three `clipboard.setText(AnnotatedString(...))`
call sites — encrypt result, decrypt result, exchange copy-key —
write directly with no expiration. The setting is currently
decorative.

**Android implementation plan**
- New singleton `ClipboardHelper` (Hilt `@Singleton`, injects
  `Context` + `SharedPreferences`)
- Reads the auto-clear pref synchronously at copy time
- Writes via `ClipboardManager.setPrimaryClip` with the
  `ClipDescription.EXTRA_IS_SENSITIVE` flag on Android 13+ so the
  preview doesn't leak
- `Handler.postDelayed` clears with `ClipData.newPlainText("", "")`
  after the configured interval
- Three call sites in `Screens.kt` (encrypt + decrypt) and
  `ExchangeScreen.kt` (copy key) get swapped to call
  `clipboardHelper.copy(text)` instead of `clipboard.setText(...)`

**iOS port notes (when porting)**
iOS PGPony already has this working — `AppState.copyToClipboard`
uses the iOS 16+ `UIPasteboard.setItems` with `.expirationDate` and
the `clipboardCountdown` published property. Settings has the
toggle + interval picker. **No iOS port needed** — this Android
update is bringing Android to parity with iOS, not the other way
around.

**Files (Android, when built)**
- NEW: `app/src/main/java/com/pgpony/android/ui/util/ClipboardHelper.kt`
- MOD: `app/src/main/java/com/pgpony/android/ui/encrypt/Screens.kt`
- MOD: `app/src/main/java/com/pgpony/android/ui/exchange/ExchangeScreen.kt`

---

## NeighCheck

### NeighCheck 1 — Pull-to-refresh on Jobs + Shifts

**Built:** 2026-05-12 · versionCode 2, versionName "1.0.1"
(combined with NeighCheck 2 into a single Play upload at
versionCode 3 / "1.0.2")

**User-visible behavior**
- Pull down on the Jobs list to trigger a sync
- Pull down on the Shifts list to trigger a sync
- Inline error banner appears if the sync fails; tap "Dismiss" to
  clear

**Android implementation**
- New shared composable `ui/shared/RefreshErrorBanner.kt`. Notably,
  the Dashboard's existing `ErrorBanner` (private to DashboardScreen)
  has the dismiss button visually present but unwired (`@Suppress
  ("UNUSED_EXPRESSION") onDismiss` at the bottom). The new shared
  banner properly wires `.clickable(onClick = onDismiss)`. Dashboard
  still uses its broken local copy; left untouched to keep this
  update small.
- `JobsViewModel` and `ShiftsViewModel` inject `AuthManager` +
  `SyncManager`. Each gains `isRefreshing`, `refreshError`,
  `refresh()`, `dismissError()` — mirroring `DashboardViewModel` line-
  for-line (re-entry guard, signed-out 300ms shimmer fallback,
  `SyncResult` → UI mapping).
- Screens wrap their existing body in `PullToRefreshBox` (Material3
  1.3+ stable API). Empty state is rendered inside a LazyColumn item
  with `.fillParentMaxSize()` so pull works even when there are zero
  rows.

**iOS port notes**
SwiftUI has `.refreshable { await viewModel.refresh() }` built in —
attach to the `List` or `ScrollView`. Much simpler than the
Android pattern.
- iOS `JobListView` / `ShiftListView` → add `.refreshable` on the
  List
- iOS view models add `func refresh() async` that calls
  `syncManager.syncAll()` and awaits
- Error banner: SwiftUI `Section` with red background + Button to
  dismiss, or an alert(). iOS doesn't need our `RefreshErrorBanner`
  abstraction.

**Files touched (Android)**
- NEW: `app/src/main/java/com/neighcheck/app/ui/shared/RefreshErrorBanner.kt`
- MOD: `app/src/main/java/com/neighcheck/app/ui/jobs/JobsViewModel.kt`
- MOD: `app/src/main/java/com/neighcheck/app/ui/jobs/JobsScreen.kt`
- MOD: `app/src/main/java/com/neighcheck/app/ui/shifts/ShiftsViewModel.kt`
- MOD: `app/src/main/java/com/neighcheck/app/ui/shifts/ShiftsScreen.kt`

**iOS counterpart files (when porting)**
- MOD: iOS equivalent of JobListView (likely `Views/JobListView.swift`
  or under `Views/Settings/`)
- MOD: iOS equivalent of ShiftListView (likely `Views/ShiftListView.swift`)
- MOD: corresponding view models with `func refresh() async`

---

### NeighCheck 2 — Pull-to-refresh on Mileage + Calendar

**Built:** 2026-05-12 · combined with NeighCheck 1 into versionCode 3
/ versionName "1.0.2"

**User-visible behavior**
- Pull down on the Mileage list to trigger a sync (now works in
  empty state too)
- Pull down on the Calendar to refresh both logged and scheduled
  shifts
- Same inline error banner / dismiss UX as NeighCheck 1

**Android implementation**
- Extends the exact pattern from NeighCheck 1 to two more screens.
- `MileageListViewModel` + `CalendarViewModel` get the same refresh
  plumbing (AuthManager + SyncManager, four new state members,
  refresh/dismissError).
- `MileageListScreen`: extended the existing private `EntriesList`
  composable to accept `refreshError` + `onDismissError` and to
  render the empty state as a `fillParentMaxSize()` item — single
  LazyColumn that handles both populated and empty cases.
- `CalendarScreen`: wrapped the existing top-level LazyColumn in
  `PullToRefreshBox`. Refresh banner prepended as the first item
  when an error is present. Month grid / day summary items
  unchanged.
- Sync was verified: `MILEAGE_ENTRY` and `SCHEDULED_SHIFT` are both
  in `SyncModelType`, so pull moves real data.

**iOS port notes**
Same as NeighCheck 1 — `.refreshable { }` on each list.
- iOS Mileage view → `.refreshable`
- iOS Calendar view → `.refreshable` on whichever scrollable
  container hosts the month grid + day summary

**Files touched (Android)**
- MOD: `app/src/main/java/com/neighcheck/app/ui/mileage/MileageListViewModel.kt`
- MOD: `app/src/main/java/com/neighcheck/app/ui/mileage/MileageListScreen.kt`
- MOD: `app/src/main/java/com/neighcheck/app/ui/calendar/CalendarViewModel.kt`
- MOD: `app/src/main/java/com/neighcheck/app/ui/calendar/CalendarScreen.kt`

**iOS counterpart files (when porting)**
- MOD: iOS Mileage list view + view model
- MOD: iOS Calendar view + view model

---

## EntityDesk

### EntityDesk 1 — "Updated X ago" row on entity cards

**Built:** 2026-05-12 · versionCode 3, versionName "1.0.2"
(after a prior versionCode 2 upload)

**User-visible behavior**
- Each entity row on the Dashboard now shows a third metadata line
  below the state/type row: `Updated 2d ago` (or `5m ago`, `3h ago`,
  `May 9`, `Mar 12, 2025` depending on age)
- Hidden cleanly when `entity.updatedAt` is null or unparseable

**Android implementation**
- New helper `core/util/RelativeTime.kt`. Parses the server's
  `yyyy-MM-dd HH:mm:ss` UTC timestamp (or a bare `yyyy-MM-dd`) and
  returns a short relative string. Thresholds: `just now` / `Xm ago`
  / `Xh ago` / `Xd ago` / `MMM d` / `MMM d, yyyy`. Returns null on
  null/blank/unparseable input.
- Parsing mirrors `feature/share/ShareFormat.parseDate` exactly so
  the two stay consistent.
- `DashboardScreen.EntityRow` adds a third `Text` row below
  state/type. Conditional render based on null return from helper.
- Note this is "Updated" (server modification time), NOT "Last
  opened" (device-local viewing). The latter would require local
  SharedPreferences/Room tracking and offers no value for
  shared-entity scenarios where you and an advisor see the same
  data.

**iOS port notes**
iOS has this built in. Options, easiest first:
- `Text(date, style: .relative)` — auto-updating, returns "2 days
  ago" etc. (iOS 15+). Note: returns slightly different phrasing
  than our Android format (`2 days ago` vs `2d ago`).
- `RelativeDateTimeFormatter` for full control:
  ```swift
  let f = RelativeDateTimeFormatter()
  f.unitsStyle = .abbreviated  // "2d ago"
  f.localizedString(for: date, relativeTo: Date())
  ```
- For matching exact Android thresholds, write a tiny Swift
  equivalent of `RelativeTime.swift` with the same buckets.

The Android helper's parsing logic for `yyyy-MM-dd HH:mm:ss` UTC →
ISO8601 / `Date` translation in Swift is a one-liner with
`ISO8601DateFormatter` (with custom format options) or a custom
`DateFormatter`.

**Files touched (Android)**
- NEW: `app/src/main/java/com/entitydesk/app/core/util/RelativeTime.kt`
- MOD: `app/src/main/java/com/entitydesk/app/feature/dashboard/DashboardScreen.kt`

**iOS counterpart files (when porting)**
- NEW: `Sources/Core/Util/RelativeTime.swift` (or use built-in
  `Text(date, style: .relative)` directly)
- MOD: iOS entity list view (`Views/EntityListView.swift` or wherever
  the row is rendered)

---

### EntityDesk 2 — Loading skeletons (Dashboard + Entity Detail)

**Built:** 2026-05-12 · versionCode 4, versionName "1.0.3"

**User-visible behavior**
- Dashboard initial cold-load: instead of a centered spinner, 5
  entity-row placeholders pulse softly (alpha 0.5 → 1.0 → 0.5 over
  1.2s), matching the real EntityRow geometry — icon block, name
  bar, state/type bar, "Updated" bar
- Entity Detail initial load: HeaderCard-shaped skeleton + 3
  section-card placeholders, same pulse
- Pull-to-refresh on populated screens does NOT trigger skeletons —
  existing content stays on screen during sync
- The other spinner at EntityDetailScreen line ~680 (inline section
  operation) is intentionally left as a spinner — different surface

**Android implementation**
- New `core/util/SkeletonShimmer.kt` with two primitives:
  - `Modifier.shimmerPulse()`: alpha animation via
    `rememberInfiniteTransition` + `animateFloat` +
    `infiniteRepeatable(tween(1200, LinearEasing),
    RepeatMode.Reverse)`
  - `SkeletonBox(width, height, cornerRadius)`: rounded
    `surfaceVariant` Box with the shimmer modifier applied
- Flat alpha pulse, not a translating gradient — cleaner at small
  sizes, no GPU/battery cost on long pages
- `DashboardScreen.DashboardLoadingSkeleton`: private composable
  with 5 skeleton rows + a section-header skeleton. Gated by the
  same condition that gated the old spinner.
- `EntityDetailScreen.EntityDetailLoadingSkeleton`: private
  composable with a header skeleton + 3 section card skeletons.

**iOS port notes**
iOS has `.redacted(reason: .placeholder)` built in. Two approaches:
- **Built-in path (recommended):** wrap the actual `EntityRow` or
  `HeaderCard` in `.redacted(reason: .placeholder)` with stub data.
  Pulse with `.opacity` + `.animation(.easeInOut(duration: 0.6)
  .repeatForever(autoreverses: true), value: pulse)`. ~5 lines, no
  custom geometry needed.
- **Custom path (matches Android exactly):** port `SkeletonShimmer`
  → `SkeletonShimmer.swift` with `@State var alpha: Double` driven
  by `.onAppear { withAnimation(.linear(duration: 1.2)
  .repeatForever(autoreverses: true)) { alpha = 1.0 } }`. Build
  `SkeletonBox` view as a `RoundedRectangle().fill(Color(.systemGray5))
  .opacity(alpha)`.

Recommend the built-in path — `.redacted` is idiomatic SwiftUI and
gives you the structural preview for free.

**Files touched (Android)**
- NEW: `app/src/main/java/com/entitydesk/app/core/util/SkeletonShimmer.kt`
- MOD: `app/src/main/java/com/entitydesk/app/feature/dashboard/DashboardScreen.kt`
- MOD: `app/src/main/java/com/entitydesk/app/feature/entity/EntityDetailScreen.kt`

**iOS counterpart files (when porting)**
- MOD: iOS EntityListView / DashboardView for the dashboard
  skeleton state
- MOD: iOS EntityDetailView for the detail skeleton state
- OPTIONAL NEW: `Sources/Core/UI/SkeletonShimmer.swift` if going the
  custom path

---

## Cross-cutting iOS port considerations

A few patterns appear in multiple updates that are worth handling
once when iOS porting begins:

**1. Sync trigger primitive.** Android's `SyncManager.syncAll()`
returns a `SyncResult` sealed class (`Success` / `ServerError`
/ `NetworkError` / `NotAuthenticated`). iOS NeighCheck likely has
an equivalent or can add `func syncAll() async throws ->
SyncResult`. Build this once, then `.refreshable` handlers across
Jobs / Shifts / Mileage / Calendar all become two-liners.

**2. Relative-time formatting.** EntityDesk 1 introduces it but
PGPony and NeighCheck both have list rows that could benefit too
(message timestamps, shift dates). Centralize early in
`Sources/Core/Util/RelativeTime.swift` rather than per-app.

**3. Loading skeletons.** EntityDesk 2 introduces them; PGPony's
message lists and NeighCheck's dashboard could use them on slow
network. `.redacted(reason: .placeholder)` makes this a 1-line
addition anywhere you have content with stub data.

---

## Maintenance notes

- Each update entry follows the same shape:
  user-visible / Android impl / iOS port notes / files. Keep this
  consistent so the doc stays scannable.
- When an iOS port lands, change the iOS column in the summary
  table to `Built (vN)` and add a "iOS port shipped" line at the
  bottom of the relevant entry with the iOS version code.
- New Android updates go at the end of the relevant app section,
  numbered sequentially per-app.
- Keep "Files touched" current — when an iOS reviewer asks
  "what changed in this submission," cherry-picking entries from
  here gives a clean delta.
