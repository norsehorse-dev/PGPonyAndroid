# RC build, sign, deploy (PGPony Android)

The RC loop: build the foss APK locally, sign it with the default gpg key, and
push it to pgpony.app. No reproducibility gate, no git tag. All commands run in
the local terminal.

Fill in `<X.Y.Z>` (the release, e.g. 4.4.0) and `<N>` (the RC number).

## 1. Build

```
./gradlew :app:assembleFossRelease
```

Output: `app/build/outputs/apk/foss/release/app-foss-release.apk`.
Copy it out under the release name:

```
cp app/build/outputs/apk/foss/release/app-foss-release.apk /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk
```

## 2. Sign and hash

Detached armored signature with the default gpg signing key, plus the download
hash:

```
gpg --detach-sign --armor /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk
shasum -a 256 /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk | tee /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk.sha256
```

That writes `PGPony-<X.Y.Z>-RC<N>-foss.apk.asc` beside the APK.

## 3. Deploy to pgpony.app

scp the three files to the `apps` host, then ssh in and move them into place
under /var/www/pgpony with sudo. All RCs of one release share the
`<X.Y.Z>-RC-foss/` directory.

```
scp /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk.asc /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk.sha256 apps:/tmp/
ssh apps "sudo mkdir -p /var/www/pgpony/rc/<X.Y.Z>-RC-foss && sudo mv /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk.asc /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk.sha256 /var/www/pgpony/rc/<X.Y.Z>-RC-foss/"
```

Live at:
`https://pgpony.app/rc/<X.Y.Z>-RC-foss/PGPony-<X.Y.Z>-RC<N>-foss.apk`
(`.asc` and `.sha256` beside it). Confirm the link resolves before announcing.

## 4. Announce

Post the link in the relevant issues with the retest ask. It installs in place
over the tester's current copy, F-Droid included, so no uninstall.

## 5. F-Droid: no per-release recipe change

PGPony's fdroiddata recipe uses `AutoUpdateMode: Version` with
`UpdateCheckMode: Tags`. F-Droid detects each new `v*` tag and builds it
on its own, so there is NO fdroiddata edit per release: pushing the tag and
publishing the GitHub release asset (the `binary:` URL) is all that is
needed for F-Droid to pick the version up. This overrides the generic
playbook's "step 8: new fdroiddata build entry" for this repo.

Only touch the recipe when something structural changes: the signing key
(`AllowedAPKSigningKeys`), the gradle flavor or task, the release-asset
filename pattern, or the minSdk/targetSdk the build needs.
