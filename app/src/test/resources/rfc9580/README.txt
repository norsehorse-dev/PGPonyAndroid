RFC 9580 Appendix A test vectors
================================

This directory holds the canonical OpenPGP v6 test vectors from RFC 9580
Appendix A, used by RFC9580VectorTest to regression-lock PGPony's v6 consume
paths (parse / verify / decrypt) against the spec.

The .asc files are NOT checked in here on purpose — they are pulled verbatim
from rfc-editor.org by the fetch script so there is zero transcription risk:

    ./tools/fetch_rfc9580_vectors.sh

That writes:
    a3_cert.asc       A.3    Sample Version 6 Certificate
    a4_secret.asc     A.4    Sample Version 6 Secret Key (unlocked)
    a6_cleartext.asc  A.6    Sample Cleartext Signed Message
    a7_inline.asc     A.7    Sample Inline-Signed Message
    a8_encrypted.asc  A.8.5  Complete X25519-AEAD-OCB Encrypted Packet Sequence

Until the script is run, RFC9580VectorTest skips (Assume) rather than fails, so
CI stays green. Once the vectors are present the tests lock the v6 paths.

If a vector fails to carve (RFC formatting drift), copy the relevant armored
block out of https://www.rfc-editor.org/rfc/rfc9580.txt into the matching file
by hand — the test only needs the BEGIN/END block.
