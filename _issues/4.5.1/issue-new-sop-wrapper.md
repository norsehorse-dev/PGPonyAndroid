Tracking issue for a Stateless OpenPGP (SOP) command-line wrapper around PGPony's Android crypto, so the implementation can join the sequoia-pgp OpenPGP interoperability test suite.

Context from #56: @hko-s suggested this as the canonical way to test an OpenPGP implementation. The interop suite runs extensive roundtrip tests against every other implementation in the set, which is better coverage than anything I can test against on my own.

Scope:
- A stateless CLI front end over the same crypto the app uses (generate, encrypt, decrypt, sign, verify, armor, dearmor, and the rest of the SOP command set), per draft-dkg-openpgp-stateless-cli.
- Runs headless with no app state, so the interop harness can drive it.
- Wire it into the interop suite configuration once the CLI passes the SOP test vectors.

Separate from the app release cadence. References: draft-dkg-openpgp-stateless-cli-16, and the interop suite at sequoia-pgp.gitlab.io/openpgp-interoperability-test-suite.

Not started, filing so it is tracked.
