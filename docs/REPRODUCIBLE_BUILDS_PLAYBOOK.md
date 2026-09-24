# Reproducible Builds Playbook, Android / F-Droid

Version 1.0, 9 August 2026. Written after the PGPony 4.1.1 verification
failure (PGPonyAndroid issues #4, #23, #28; fdroiddata job 15796256381) and
generalized for every NorseHorse Android app that ships through F-Droid's
binary-reproducible pipeline. Everything in here was learned by breaking it
first; the incidents are cited inline so future debugging can start from
what actually happened rather than from theory.

Companion files, kept next to this playbook and in each app repo:

- `verify_repro.sh`: the release gate script (repo location: `tools/`)
- `reproducible.yml`: the CI workflow (repo location: `.github/workflows/`)

---

## 1. What this playbook covers

F-Droid can publish an app two ways. Either they sign the build with their
own key, or (the mode all our apps use) they build the app themselves from
the tagged source, copy the developer's signature from the developer's
published APK onto their build, and publish the developer-signed APK only
if that verification succeeds. The second mode means every release must be
bit-for-bit reproducible: their Debian buildserver's Gradle output must
match ours exactly, or the release does not ship.

This playbook covers: setting up a new app so its builds are reproducible,
the release procedure that guarantees the uploaded APK verifies, the
automated gate that enforces it, and the diagnosis toolbox for when
something still fails.

## 2. How F-Droid's verification actually works

Understanding the exact mechanics is what makes failures diagnosable.
Their CI does the following (visible in any build log):

1. Clones the tagged commit named in the fdroiddata recipe and runs the
   recipe's Gradle task (for us: `assembleFossRelease`) on their Debian
   buildserver.
2. Downloads the developer-supplied reference APK from the `binary:` URL
   in the recipe (our GitHub release asset).
3. Strips any signature from their own build (a clean clone has no
   keystore, so our Gradle config falls back to debug signing; they strip
   that off).
4. Uses `apksigcopier` to copy the APK Signing Block from the reference
   APK onto their stripped build.
5. Runs `apksigner verify` on the result. The v2/v3 signature contains
   digests over the entire ZIP (entries, central directory, end-of-
   central-directory record). If their ZIP bytes differ ANYWHERE from the
   bytes the developer signed, this fails with
   `CHUNKED_SHA256 digest mismatch. DOES NOT VERIFY`.
6. If verification fails, they unpack both APKs and print a file-level
   diff (`classes.dex differ`, etc.) in the log, and the job keeps its
   artifacts: `tmp/` contains their built APK, which is the single most
   valuable diagnostic object that exists. Grab it early; artifacts
   expire.

Two consequences worth internalizing:

- The check is BYTE level over the whole ZIP, not content level. Two APKs
  containing identical files can still fail if the ZIP layout differs
  (entry order, alignment padding, extra fields). This is exactly what
  the apksigner build-tools 35 alignment rewrite triggers (section 5,
  rule R3).
- The signature itself is excluded from the digest, which is why the
  signature can be copied across at all. Everything else is covered.

## 3. Vocabulary: three different "the same APK"

Confusing these three cost multiple releases. Be precise.

1. **Whole-file SHA-256** (`shasum -a 256 file.apk`). Changes whenever the
   signature changes, so it is only meaningful for "is this download the
   file I published". Publish it for downloaders.
2. **Byte-identical modulo signature**: strip the APK Signing Block from
   both files and compare the remaining bytes. This is the equivalence
   F-Droid's verification requires. `verify_repro.sh` cannot prove this
   one directly against F-Droid before submission, but signing via Gradle
   in the clean clone (rule R3) guarantees it by construction.
3. **Content-identical**: every file inside the ZIP has identical bytes,
   ignoring ZIP metadata and signature files. This is what
   `verify_repro.sh compare` proves and what the **content hash**
   summarizes: the SHA-256 of the sorted per-entry SHA-256 manifest,
   signature files excluded. It is filesystem-independent and identical
   for signed and unsigned variants of the same build. Publish it for
   people rebuilding from source.

Content-identical plus Gradle-produced layout equals byte-identical modulo
signature in practice, because Gradle's zipflinger writes entries
deterministically. The PGPony 4.1.1 endgame proved this empirically: a Mac
clean-clone Gradle build and F-Droid's Debian build were byte-identical
with signatures stripped.

## 4. One-time setup for a new app

### 4.1 Pin every toolchain input in-tree

Audit and pin, in the repo, so the buildserver cannot resolve anything
differently:

| Input | Where | Notes |
|---|---|---|
| Gradle | `gradle/wrapper/gradle-wrapper.properties` | exact `-bin.zip` version |
| AGP | root `build.gradle.kts` | exact version, never `+` |
| Kotlin + Compose plugin | root `build.gradle.kts` | exact |
| buildToolsVersion | `app/build.gradle.kts` android block | pin to what AGP already resolves, bump only with AGP |
| compileSdk / targetSdk | `app/build.gradle.kts` | exact |
| Every dependency | `app/build.gradle.kts` | no `+`, no `latest.release`, BOMs pinned |

Audit command for dynamic versions (should print nothing):

```
grep -rn --include=build.gradle.kts -e '+"' -e 'latest' app/ build.gradle.kts
```

Optional hardening: Gradle dependency locking
(`dependencyLocking { lockAllConfigurations() }` plus a committed
lockfile). PGPony's 4.1.0 investigation showed the resolved set was stable
without it, but the lockfile turns silent drift into loud failure.

### 4.2 Determinism flags in `app/build.gradle.kts`

```kotlin
buildTypes {
    release {
        vcsInfo.include = false
    }
}
dependenciesInfo {
    includeInApk = false
    includeInBundle = false
}
```

`vcsInfo.include = false` keeps the git-state textproto out of the APK
(otherwise the developer tree and the F-Droid clone embed different VCS
state). `dependenciesInfo` removes the Google-signed opaque blob, which
F-Droid wants gone anyway. AGP already normalizes ZIP entry timestamps to
1981-01-01; do not add tooling that rewrites them.

### 4.3 Signing config that degrades to debug

The clean clone and the F-Droid buildserver have no keystore, so signing
must be optional:

```kotlin
val keystorePropertiesFile = rootProject.file("keystore.properties")
signingConfig = if (keystorePropertiesFile.exists())
    signingConfigs.getByName("release") else signingConfigs.getByName("debug")
```

`keystore.properties` is gitignored, holds `storeFile`, `storePassword`,
`keyAlias`, `keyPassword`. This exact pattern is what makes rule R3's
signing flow work.

### 4.4 Install the gate

Copy into the repo and commit:

- `tools/verify_repro.sh` (chmod 755)
- `.github/workflows/reproducible.yml`

Per-app knobs, if the app differs from the standard layout, are
environment variables read by the script: `REPO_URL` (defaults to the
checkout's origin remote), `GRADLE_TASK` (default
`:app:assembleFossRelease`), `APK_REL_PATH` (default
`app/build/outputs/apk/foss/release/app-foss-release.apk`). Set them in
the workflow env block too if overridden.

### 4.5 fdroiddata recipe essentials

For the binary-reproducible mode the recipe (metadata/<appid>.yml in
fdroiddata) needs:

```yaml
Builds:
  - versionName: X.Y.Z
    versionCode: NNN
    commit: <full sha of the tag>
    subdir: app
    gradle:
      - foss
    binary:
      https://github.com/norsehorse-dev/<Repo>/releases/download/v%v/<App>-%v-foss.apk
AllowedAPKSigningKeys: <sha256 of the signing certificate>
AutoUpdateMode: Version
UpdateCheckMode: Tags
```

`%v` expands to versionName, so the release asset filename must follow the
`<App>-X.Y.Z-foss.apk` pattern exactly. `AllowedAPKSigningKeys` is the
SHA-256 of the DER certificate; print it with
`apksigner verify --print-certs` (any build-tools version is fine for
verifying, the restriction in R3 is about signing).

## 5. The rules, each bought with a failure

**R1. Never build anything you publish from a working tree.** Incremental
R8 and warm daemons do not produce byte-identical output to a clean run
(4.1.0 verification, §7), and a working tree can silently differ from the
commit you tagged. 4.1.1 shipped an APK compiled from a variant of three
files that never got committed; F-Droid caught it (#28). The working tree
is for development, period.

**R2. Nothing uploads until the gate passes on the exact file being
uploaded.** `verify_repro.sh rebuild <tag> <candidate.apk>` proves the tag
builds deterministically twice from clean clones and that the candidate
content-matches. 4.1.1's clean-clone check was run but never compared
against the signed upload; the gate closes that gap by taking the
candidate as an argument.

**R3. Sign by rebuilding in the gate's clean clone with the keystore
present. Never re-sign with apksigner from build-tools 35 or newer.**
apksigner from 35+ rewrites ZIP alignment (0xd935 extra fields replace
Gradle's zero padding), so the signed file stops being byte-identical to
any Gradle build and F-Droid's verification fails on layout with a digest
mismatch even though every file inside matches. F-Droid's docs confirm 34
works and newer fails; `--alignment-preserved` on newer versions also
works where available. Discovered 9 Aug 2026 when the first replacement
4.1.1 asset was apksigner-signed; the failure was caught by simulation
before F-Droid retried. The Gradle route has no such trap: only the
package/sign tasks rerun, the verified dex is untouched, and the layout is
the same zipflinger layout the buildserver produces.

**R4. Never extract APKs to a filesystem to compare or hash them.** AGP's
shortened resource names collide case-insensitively (PGPony 4.1.1 has 12
pairs like `res/IN.xml` and `res/In.xml`). On macOS (case-insensitive)
extraction silently drops one of each pair, corrupting any comparison and
producing machine-dependent hashes. `verify_repro.sh` reads the ZIP
directly with Python for exactly this reason. If you must eyeball files,
extract on Linux.

**R5. Compare clone against clone; a candidate is only ever compared to a
fresh clean build.** Established in the 4.1.0 verification and still
correct.

**R6. Publish the content hash, not an "unsigned APK hash".** A clean
clone build is debug-signed by the fallback config, so its whole-file hash
is machine-specific and nobody else can ever match it (this made 4.1.1's
published "unsigned" hash useless). The content hash is reproducible by
anyone from source.

**R7. Record every verification result with its diff.** Three failures
with no recorded diff is why the PGPony problem survived from 4.0.1 to
4.1.1. The gate prints everything needed; keep the output with the release
notes draft.

## 6. Standard release procedure

Assumes: version bumped and committed, device validation done, release
notes drafted. `<tag>` is like `v4.2.0`, `<App>` like `PGPony`.

Step 1, tag and push (starts the CI gate automatically):

```
git tag <tag>
git push origin main --tags
```

Step 2, run the local gate. There is no candidate yet, so run it bare;
this proves determinism and produces the canonical clean build:

```
tools/verify_repro.sh rebuild <tag>
```

Note the printed work directory (call it `<work>`) and the content hash.

Step 3, produce the signed release APK inside the verified clone:

```
cp keystore.properties <work>/srcA/
cd <work>/srcA
env GRADLE_USER_HOME=<work>/gradleA ./gradlew --no-daemon :app:assembleFossRelease
cp app/build/outputs/apk/foss/release/app-foss-release.apk /tmp/<App>-X.Y.Z-foss.apk
```

Step 4, gate the exact file that will be uploaded:

```
cd <repo>
tools/verify_repro.sh compare /tmp/<App>-X.Y.Z-foss.apk <work>/buildA.apk
```

Must print IDENTICAL. The content hash printed here must equal step 2's.

Step 5, confirm the CI legs passed (Actions tab, both JDKs green on the
determinism step; the release-asset comparison is skipped until the asset
exists).

Step 6, sign and publish:

```
gpg --detach-sign --armor --local-user 0x53F9798E4919DE62 --output /tmp/<App>-X.Y.Z-foss.apk.asc /tmp/<App>-X.Y.Z-foss.apk
shasum -a 256 /tmp/<App>-X.Y.Z-foss.apk
gh release create <tag> /tmp/<App>-X.Y.Z-foss.apk /tmp/<App>-X.Y.Z-foss.apk.asc --title "<App> X.Y.Z" --notes-file docs/releases/RELEASE_NOTES_X.Y.Z.md
```

Release notes carry BOTH hashes with their meanings: the whole-file
SHA-256 for downloaders, the content hash for rebuilders (see the 4.1.1
release body for the canonical wording).

Step 7, re-run the workflow on the tag (Actions, reproducible-check, Run
workflow) so the release-asset comparison runs end to end against the
published file.

Step 8, fdroiddata: new build entry with the tag's commit sha, versionName
and versionCode, and the binary URL. Update `CurrentVersion` /
`CurrentVersionCode`. Then clean up `<work>`.

## 7. Gate script reference (`tools/verify_repro.sh`)

```
tools/verify_repro.sh rebuild <tag> [candidate.apk]
tools/verify_repro.sh compare <a.apk> <b.apk>
tools/verify_repro.sh content-hash <apk>
```

- `rebuild`: clones `<tag>` twice into isolated roots (separate
  `GRADLE_USER_HOME`s, `--no-daemon`), builds each, fails unless the two
  builds are content-identical, then fails unless the candidate (if
  given) matches them. Prints per-dex SHA-256s and the R8 markers. Keeps
  the work directory so `buildA.apk` is available for step 3. Requires
  network (clones and dependency downloads) and an Android SDK
  (`ANDROID_HOME`, `ANDROID_SDK_ROOT`, or the default macOS/Linux
  locations).
- `compare`: content comparison of two APKs via per-entry manifest,
  ignoring only `META-INF/*.SF|*.RSA|*.DSA|*.EC|MANIFEST.MF`. Never
  touches the filesystem with entry contents (R4).
- `content-hash`: the publishable number (section 3).

Exit code is nonzero on any mismatch, so it can gate shell pipelines and
CI. What it does NOT prove: byte-layout identity against a signer that
rewrote the ZIP; that hazard is eliminated at the source by R3.

## 8. CI workflow reference (`.github/workflows/reproducible.yml`)

Triggers: every `v*` tag push, plus manual dispatch with any tag.
Matrix: Temurin JDK 17 and 21 on ubuntu-24.04, `fail-fast: false`.
Each leg runs the same `rebuild` gate (Linux mirrors the F-Droid
buildserver), then downloads the `<App>-*-foss.apk` release asset if one
exists and runs `compare` against the fresh build; a missing asset is
skipped, not failed. The unsigned build uploads as a run artifact per JDK.

Reading the matrix: both legs green means the build is deterministic on
Linux under either JDK and (when the asset existed) the published APK
matches a Linux clean build. One leg failing the asset comparison while
the other passes would mean the toolchain output depends on the JDK; the
canonical JDK is then whichever matches F-Droid's buildserver, and the
divergence should be pinned in-tree (Gradle Java toolchain block). As of
Aug 2026 PGPony's output is identical under both, and macOS Temurin 21
matches Debian, so no toolchain pin is needed.

## 9. Failure triage

First: pull the failing F-Droid job's artifacts IMMEDIATELY (section
10.1); they expire. Then find your row:

| Symptom | Cause | Fix |
|---|---|---|
| Gate: two clean builds differ from each other | Real nondeterminism: floating/transitive dependency drift, or toolchain nondeterminism | Add dependency locking; diff `META-INF/*.version` entries between the builds; pin what moved |
| Gate: builds match each other, candidate differs | Candidate built from a working tree or wrong source (this was 4.1.1) | Rebuild candidate per R1/R3 from the clean clone |
| Gate build fails: SDK location not found | Clean clone has no `local.properties` | Script exports `ANDROID_HOME`; set it if the SDK is somewhere unusual |
| F-Droid: `classes*.dex` + `baseline.prof` differ | The prof is DERIVED from the dex; this is one dex-level cause, not two problems. Either wrong source (see above) or JDK/toolchain divergence | Diff their APK against yours at method level (10.4). Three or four specific methods: source mismatch. Broad diffs: toolchain; compare JDKs, pin via Gradle toolchain |
| F-Droid: digest mismatch (`DOES NOT VERIFY`) but their diff shows NO content differences, or `compare` against their APK says IDENTICAL | ZIP layout drift: the reference was signed by a tool that rewrote the archive (apksigner from build-tools 35+) | Re-sign per R3, replace the asset |
| F-Droid: `resources.arsc` or `res/**` differ | AAPT2 version or resource input differs | Check AGP version resolution both sides; AAPT2 ships with AGP |
| F-Droid: `META-INF/<lib>.version` files differ | Different resolved dependency set; the filename names the library | Pin that dependency; consider a lockfile |
| F-Droid: `assets/dexopt/baseline.prof` differs ALONE | Profgen/AGP version differs (rare with AGP pinned) | Verify AGP resolution; last resort, disable baseline profiles for the foss flavor |
| Whole-file hashes differ but everything above passes | You are comparing a signed file to an unsigned/debug-signed one | Expected; use content hash |

## 10. Deep diagnosis toolbox

### 10.1 Pull the F-Droid job artifacts

The failing job URL comes from the maintainer's comment or the fdroiddata
MR pipeline. Artifacts via the GitLab API (works with plain curl):

```
curl -L -o fdroid-job-<JOBID>.zip "https://gitlab.com/api/v4/projects/fdroid%2Ffdroiddata/jobs/<JOBID>/artifacts"
```

Inside: `tmp/<appid>_<versioncode>.apk` is their kept failed build,
`unsigned/` their staging copy, `repo/` an index preview. Their built APK
is ground truth for what the buildserver produced from your tag.

### 10.2 Compare their build against your release

```
tools/verify_repro.sh compare <their.apk> <your-release.apk>
```

IDENTICAL plus their job still failing means layout (triage row 5).
Differences print per file, with dex hashes and R8 markers.

### 10.3 Simulate their verification exactly

`pip install apksigcopier`, then reproduce steps 3 to 5 of section 2: strip
the debug signature from their build, copy your signing block onto it,
require byte identity with your release:

```
python3 -c "
import apksigcopier, struct
src, out_path = '<their.apk>', 'their-unsigned.apk'
data = open(src,'rb').read()
off, blk = apksigcopier.extract_v2_sig(src)
cd = off + len(blk)
eocd = data.rfind(b'PK\x05\x06')
out = bytearray(data[:off] + data[cd:])
p = eocd - len(blk)
out[p+16:p+20] = struct.pack('<I', off)
open(out_path,'wb').write(out)
"
apksigcopier copy <your-release.apk> their-unsigned.apk /tmp/sigcopy.apk
cmp /tmp/sigcopy.apk <your-release.apk>
```

`cmp` silent (byte-identical) means their retry mathematically must
verify. This simulation is what caught the apksigner alignment problem
before F-Droid did.

### 10.4 Find WHICH classes differ

`pip install androguard`, then index both dex sets by class/method and
compare code sizes; identical method sets with a handful of size diffs
points at specific source files, broad diffs point at the toolchain:

```
python3 -c "
import logging; logging.disable(logging.CRITICAL)
from androguard.core.dex import DEX
def index(p):
    d = DEX(open(p,'rb').read())
    return {(c.get_name(),m.get_name(),m.get_descriptor()):
            (m.get_code().get_length() if m.get_code() else -1)
            for c in d.get_classes() for m in c.get_methods()}
a, b = index('a/classes2.dex'), index('b/classes2.dex')
print('only in a:', len(set(a)-set(b)), ' only in b:', len(set(b)-set(a)))
for k in sorted(set(a)&set(b)):
    if a[k]!=b[k]: print(k, a[k], b[k])
"
```

(Extract the dex files on LINUX per R4, or adapt to read from the zips.)
In the 4.1.1 case this reduced 32 MB of differing dex to exactly three
composable methods, which identified the root cause in minutes.

### 10.5 Reading the R8 markers

Every release dex contains `~~R8{...}` with the R8 `version` (compare
these first; they must match) and a `pg-map-id`, plus a matching
`r8-map-id-<hash>` string. The map-id is a fingerprint of the proguard
mapping and differs whenever ANY input differed, so two builds can be
"identical except map-id and its knock-on bytes" and the real diff is
elsewhere (in 4.1.1, classes.dex and classes3.dex differed ONLY by
map-id; all real change sat in classes2.dex). Normalize the marker and the
map-id string plus the dex header checksum/signature (bytes 8 to 32)
before concluding a dex "really" differs.

## 11. Fixing an already-published bad release

If F-Droid has NOT yet published the version (the recipe MR is open or
failing), replacing the GitHub release asset in place is legitimate and
faster than a new version: their retry re-downloads the `binary:` URL.
Requirements: same versionCode, built from the SAME tagged commit, signed
with the same key, and the release body updated with the new hashes plus a
dated note explaining the replacement (users who downloaded the old file
need to understand why hashes changed; state the old whole-file hash and
the scope of the binary difference). The 4.1.1 release body is the
template.

If F-Droid HAS published the version, never replace anything; cut a new
patch version through the full procedure.

Regenerate the `.asc` whenever the APK bytes change; a stale detached
signature that no longer matches is worse than none.

## 12. Working with F-Droid maintainers

- The maintainers (linsui, licaon-kter) are responsive and technical.
  Report findings concretely: what differed, what the cause was, what
  changed, and the verification already done on your side. A recorded
  failure is worth more than silence.
- Ask them to retry only after the simulation in 10.3 passes; their CI
  time is a shared resource and repeated failed retries erode trust.
- If their build ever diverges from a green gate, ask which JDK the
  buildserver used and add it to the workflow matrix before anything
  else.

## 13. Adapting to another app

Checklist for a new or existing app adopting this playbook:

1. Copy `tools/verify_repro.sh` and `.github/workflows/reproducible.yml`
   into the repo; adjust `GRADLE_TASK` / `APK_REL_PATH` env if the module
   or flavor names differ; update the workflow's asset `--pattern` to the
   app's release filename convention.
2. Work through section 4 (pinning, determinism flags, signing fallback).
3. Run `tools/verify_repro.sh rebuild <latest-tag>` once as a baseline;
   fix anything it surfaces BEFORE the next release, not during it.
4. First release under the gate: follow section 6 exactly, record the
   content hash in the release notes, and add the fdroiddata entry.
5. Add the app's signing cert SHA-256 and content-hash convention to the
   app's own docs so the recipe's `AllowedAPKSigningKeys` never has to be
   reverse-engineered.

## 14. Results log template

Keep one row per verification event, in the release's notes file:

| Date | Step | Result |
|---|---|---|
| | gate rebuild `<tag>` | pass/fail, content hash |
| | candidate compare | pass/fail, diff summary if fail |
| | CI legs (17/21) | pass/fail per leg |
| | asset uploaded | whole-file sha256 |
| | F-Droid outcome | verified / job id + artifact diff |

The 4.1.1 incident in one line each, as the worked example: reference APK
built from uncommitted variants of three files (R1); caught by F-Droid,
diagnosed via job artifacts and method-level dex diff (10.1, 10.4); first
replacement signed with apksigner 35 would have failed on layout, caught
by simulation (R3, 10.3); final asset was a Gradle-signed clean-clone
build proven byte-identical to F-Droid's own build before upload.
