#!/usr/bin/env bash
# rc_history_check.sh: check the release candidates distributed before RCs were tagged.
#
# Usage:
#   tools/rc_history_check.sh <dir with the RC APKs> [candidates file]
#
# For each line of the candidates file (default tools/rc_history_candidates.txt), finds the RC APK under
# the given directory, builds each listed commit from a clean checkout (a detached git worktree, so commits
# that only exist on remote-tracking branches such as origin/4.6.x are reachable), and compares
# content hashes (signatures ignored, same hash as tools/verify_repro.sh content-hash). Each commit is
# built once and reused for every RC that lists it.
#
# Prints one line per RC:
#   <RC> <RC content hash> MATCH <commit>
#   <RC> <RC content hash> NO MATCH <commit>:<first 12 of its content hash> ...
# A commit that does not build shows as <commit>:build-failed, with its log kept in the work directory.
#
# This is a one-off history check, not the release gate: one build per commit and a shared Gradle home.
# The release gate (tools/verify_repro.sh rebuild) builds twice from isolated roots.
#
# Environment (optional): GRADLE_TASK, APK_REL_PATH, ANDROID_HOME, WORK (work directory).

set -uo pipefail

ARCHIVE="${1:?usage: $0 <dir with the RC APKs> [candidates file]}"
REPO="$(git rev-parse --show-toplevel)"
CANDS="${2:-$REPO/tools/rc_history_candidates.txt}"
GRADLE_TASK="${GRADLE_TASK:-:app:assembleFossRelease}"
APK_REL_PATH="${APK_REL_PATH:-app/build/outputs/apk/foss/release/app-foss-release.apk}"
WORK="${WORK:-$(mktemp -d /tmp/rc-history.XXXXXX)}"
mkdir -p "$WORK"
export GRADLE_USER_HOME="$WORK/gradle"
if [ -z "${ANDROID_HOME:-}" ]; then
    for d in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
        [ -d "$d" ] && ANDROID_HOME="$d" && break
    done
fi
export ANDROID_HOME

echo "work directory: $WORK" >&2

chash() { "$REPO/tools/verify_repro.sh" content-hash "$1"; }

build() {
    local sha="$1" out="$WORK/build-$1.apk"
    if [ -f "$out" ]; then echo "$out"; return 0; fi
    if [ -f "$WORK/failed-$sha" ]; then return 1; fi
    echo "building $sha" >&2
    git -C "$REPO" worktree remove --force "$WORK/src" > /dev/null 2>&1
    rm -rf "$WORK/src"
    if git -C "$REPO" worktree add --quiet --detach "$WORK/src" "$sha" < /dev/null \
        && ( cd "$WORK/src" && ./gradlew --no-daemon "$GRADLE_TASK" ) < /dev/null > "$WORK/log-$sha.txt" 2>&1 \
        && [ -f "$WORK/src/$APK_REL_PATH" ]; then
        cp "$WORK/src/$APK_REL_PATH" "$out"
        echo "$out"
        return 0
    fi
    touch "$WORK/failed-$sha"
    return 1
}

trap 'git -C "$REPO" worktree remove --force "$WORK/src" > /dev/null 2>&1' EXIT

grep -v '^#' "$CANDS" | while read -r rc file cands; do
    [ -n "$rc" ] || continue
    apk="$(find "$ARCHIVE" -name "$file" -print -quit < /dev/null)"
    if [ -z "$apk" ]; then
        echo "$rc - MISSING $file"
        continue
    fi
    rc_hash="$(chash "$apk")"
    result=""
    tried=""
    for sha in $cands; do
        if ! b="$(build "$sha")"; then
            tried="$tried $sha:build-failed"
            continue
        fi
        h="$(chash "$b")"
        if [ "$h" = "$rc_hash" ]; then
            result="MATCH $sha"
            break
        fi
        tried="$tried $sha:${h:0:12}"
    done
    if [ -n "$result" ]; then
        echo "$rc $rc_hash $result"
    else
        echo "$rc $rc_hash NO MATCH$tried"
    fi
done
