#!/usr/bin/env bash
set -euo pipefail

RFC_URL="https://www.rfc-editor.org/rfc/rfc9580.txt"
DEST="app/src/test/resources/rfc9580"
TMP="$(mktemp -d)"
RFC="$TMP/rfc9580.txt"

mkdir -p "$DEST"
echo "Downloading RFC 9580 ..."
curl -fsSL "$RFC_URL" -o "$RFC"

total="$(grep -c '^[[:space:]]*-----BEGIN PGP' "$RFC" || true)"
echo "Armored blocks found in source: $total"
if [ "$total" -eq 0 ]; then
  echo "ERROR downloaded file has no PGP blocks; not a valid RFC text. Check $RFC_URL"
  exit 1
fi

carve() {
  title="$1"
  out="$2"
  hits="$(grep -cF "$title" "$RFC" || true)"
  awk -v t="$title" '
    index($0, t) > 0 { cap=1; blk=""; inb=0; ind=0 }
    cap && !inb && /^[[:space:]]*-----BEGIN PGP/ { inb=1; match($0, /^ */); ind=RLENGTH }
    inb {
      line=$0
      if (ind>0 && length(line)>=ind && substr(line,1,ind) ~ /^ +$/) line=substr(line,ind+1)
      blk=blk line "\n"
    }
    inb && /^[[:space:]]*-----END PGP/ { inb=0; cap=0; last=blk }
    END { printf "%s", last }
  ' "$RFC" > "$DEST/$out"
  if [ -s "$DEST/$out" ]; then
    echo "  wrote $out -> $(wc -l < "$DEST/$out" | tr -d ' ') lines [title hits: $hits]"
  else
    echo "  WARN no block carved for $out [title hits: $hits, match: $title]"
    rm -f "$DEST/$out"
  fi
}

carve "Sample Version 6 Certificate"                       a3_cert.asc
carve "Sample Version 6 Secret Key"                        a4_secret.asc
carve "Sample Cleartext Signed Message"                    a6_cleartext.asc
carve "Sample Inline-Signed Message"                       a7_inline.asc
carve "Complete X25519-AEAD-OCB Encrypted Packet Sequence" a8_encrypted.asc

rm -rf "$TMP"
echo "Done. Vectors written to $DEST"
echo "Now run: ./gradlew testDebugUnitTest --tests '*RFC9580VectorTest*'"
