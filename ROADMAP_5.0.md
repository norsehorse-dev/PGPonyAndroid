# PGPony 5.0 planning

Status: brainstorm converged, not yet scoped for implementation. This is a
direction document, not a spec. It records the bet we are making and why, so
the detailed work can be planned against it.

## The bet in one line

PGPony 5.0 turns PGPony from an app that does OpenPGP into the OpenPGP engine
that other apps call, and the reason they call it is that it is already
post-quantum. Strictly serverless. Android leads.

## Why this, why now

The 4.x line was depth: key management, GnuPG composite interop, hardware keys,
reproducible builds, safeguards. That work made PGPony the most capable serious
OpenPGP app for the people already in the issue tracker. It did not grow the
audience, because the audience for "an app you compose PGP in" is small by
nature.

Two facts change the shape of a 5.0:

- PGPony is ahead on post-quantum. ML-KEM hybrid in both directions, composite
  key interop with GnuPG 2.5.x and GPG4WIN, v6 and Ed25519. Most of the field
  is not here yet. That lead is a moat only while it is a moat, so it is worth
  spending now.
- The de-Googled Android ecosystem already has a crypto-provider pattern. Mail
  and messaging apps bind to a provider that does OpenPGP for them, rather than
  shipping their own. That provider slot has been held by one incumbent that is
  maintained slowly. It is an opening.

The strategic order is deliberate: become infrastructure first, broaden the
audience second. A solo developer cannot win a mainstream product fight
directly. But if PGPony is the engine inside the apps people already use, the
audience arrives through those apps without PGPony having to grow a large
product surface of its own. Infrastructure is the distribution.

## What 5.0 is

Two pillars, shipped as one release with one story: post-quantum, everywhere
you already work.

### Pillar 1: the provider

PGPony exposes its crypto to other apps on the device through a provider
interface. Two interfaces, built in parallel:

- Compatibility interface. Implement the existing de-facto Android OpenPGP
  provider API (the AIDL interface the incumbent defined, the one mail and
  messaging apps already bind to). An app that today requires the incumbent
  provider should be able to select PGPony instead with no code change on its
  side. This is the reach: day-one compatibility with apps that already exist.
- PQC-native interface. A clean, modern interface designed post-quantum first,
  carrying the composite-key and v6 semantics the legacy API never anticipated.
  This is the differentiator: the capabilities only PGPony can offer, exposed
  properly rather than bolted onto an old shape.

The reason to build both at once rather than one then the other is that they
serve different jobs. The compatibility interface buys immediate relevance in
the existing ecosystem. The native interface is what makes integrating with
PGPony worth more than integrating with the incumbent. One without the other is
either reach with no advantage, or advantage with no reach.

The provider is on-device inter-process communication. There is no server and
no account anywhere in it. This pillar is fully consistent with strictly
serverless.

### Pillar 2: the migration wizard

The provider is invisible plumbing. The migration wizard is the visible face of
the same claim, and it is the thing a user or a writer can actually see.

The wizard walks a person through moving their identity to post-quantum without
losing the ability to talk to people who are not there yet:

- Generate the post-quantum key.
- Cross-sign it from the existing classical key so the new key inherits the old
  key's standing.
- Produce the message that tells contacts about the new key, and track who has
  received it.
- During the transition, keep signing with a key that pre-v6 clients can
  verify, so mail stays readable for recipients whose software cannot handle v6
  or composite keys yet.

Every step is serverless. Notifications leave as a file, a QR, or through
whatever transport the recipient's own app uses. Nothing about the migration
depends on PGPony operating a directory or a relay.

The two pillars are one message. The provider makes PGPony the engine. The
wizard proves the engine is the one that carries people into the post-quantum
era. Neither ships without the other.

## What 5.0 is not

- Not a server. No relay, no key directory, no account, not optional, not
  later. Anything that needs to move between devices or people moves over QR,
  NFC, LAN, files, or the integrating app's own transport.
- Not a mainstream usability release. Hiding the crypto for non-technical users
  is the broadening step that comes after infrastructure, not part of 5.0.
- Not a rewrite. It builds on PGPonyCore-Kotlin and the existing app. The
  provider is a new surface on top of the core, not a replacement for it.

## Architecture and security

The hard part of a provider is not the crypto, it is the consent model. The
moment another app can ask PGPony to decrypt or sign, the questions are: which
apps are allowed, how does the user grant and revoke that, how is a request
from a hostile app that impersonates a trusted one prevented, and how is a
signing or decryption request surfaced to the user rather than answered
silently. The incumbent solved a version of this with per-app authorization and
consent prompts. PGPony needs its own answer, designed rather than inherited,
because the provider is the new attack surface the whole release introduces.

The leverage is PGPonyCore-Kotlin. The provider should be a thin surface over
the core that the app already uses, so the crypto path is the same one that is
already tested and reproducible. The provider adds an interface and a consent
layer, not a second implementation of anything cryptographic.

## Cross-platform reality

This flagship is Android-led by nature, and that is worth stating plainly rather
than discovering later.

- The provider pattern is an Android inter-process mechanism. It is a natural
  fit there.
- iOS has no equivalent cross-app crypto-provider mechanism. App extensions and
  the share sheet are the closest, and they are weaker. A network-based
  approach is off the table under strictly serverless. So the provider pillar
  does not port to iOS as-is; iOS parity for it is different work, not a
  recompile.
- The migration wizard does port. It is app-level logic over the shared core,
  so it can land on iOS and Desktop on their own timelines.

Going Android-first now fits this. The plan should not promise simultaneous
provider parity on iOS.

## Launch approach

Ship and let apps come. No courted launch partner. Implement the compatibility
interface well enough that apps already binding to the incumbent can switch,
document both interfaces clearly, and let adoption happen on its own. This
front-loads the risk onto the build: there is no partner validating the
integration before release, so the compatibility interface has to be correct
against real apps' expectations without a real app in the loop early. Testing
against the actual apps that use the incumbent provider, even without their
authors involved, becomes part of the work rather than an afterthought.

## Risks worth naming now

- Two interfaces in parallel is two engines at once for one developer. This is
  the heaviest path chosen deliberately. The main mitigation is that both sit on
  the same core; the cost is in the two surfaces and their tests, not in two
  crypto implementations.
- Ship-and-see means no early proof. If no app adopts the provider, the release
  is technically sound and strategically stalled. A fallback worth holding: the
  migration wizard delivers user value on its own even if provider adoption is
  slow, so 5.0 is not worthless if the ecosystem is slow to move.
- The compatibility interface is defined by someone else's implementation, not a
  clean spec. Matching it means matching real behavior, including its quirks.
  This is discovery work that cannot be fully estimated up front.
- PQC through the native interface needs apps to adopt the extensions to matter.
  The compatibility interface works day one; the native advantage accrues only
  as apps choose to use it. That is a slow curve, not a launch spike, and the
  plan should expect it.

## A sensible internal order

Both interfaces are in scope for 5.0, but they do not have to be built in
lockstep. One workable sequence inside the moonshot:

1. Provider service skeleton and consent model over the existing core. The
   security surface first, because everything else rides on it.
2. Compatibility interface to the point where one real incumbent-using app works
   end to end against PGPony.
3. Migration wizard, using the core directly. It is independent of the provider
   and gives the release a visible deliverable early.
4. PQC-native interface, once the compatibility path and the consent model are
   proven.
5. Developer-facing documentation for both interfaces, since ship-and-see lives
   or dies on how easy it is for an app author to discover and trust the
   provider.

This keeps the developer from building two interfaces at the same moment even
though both are in the release.

## What "done" looks like

- A real app that today uses the incumbent OpenPGP provider works against
  PGPony instead, unmodified.
- The native interface exposes composite-key and v6 operations that the legacy
  API cannot express.
- A user can move their identity to post-quantum through the wizard and still
  exchange mail with a pre-v6 recipient throughout the transition.
- No server, no account, no network dependency anywhere in either pillar.
- The provider path runs through PGPonyCore-Kotlin, so it inherits the existing
  reproducible, tested crypto rather than duplicating it.

## Open decisions to revisit

- The exact consent and authorization model for the provider. This is the
  biggest single design question in the release.
- How far the native interface goes in 5.0 versus what waits for 5.1.
- Whether the migration wizard's contact tracking is per-key state in the app or
  something the user exports and re-imports.
- iOS and Desktop timelines for the migration wizard, given the provider will
  not reach them in the same shape.
- Whether to publish the native interface as a small library other apps can
  depend on, or only as an on-device interface.
