# RC build, sign, publish (PGPony Android)

From 4.7.2 on, a release candidate goes through the same path as a release: a signed commit and a signed tag,
a build through the reproducibility gate from a clean clone of that tag, the same signing, and a GitHub
pre-release that links the APK to its source. pgpony.app/rc/ only mirrors what the pre-release carries.

Why: until 4.7.1, RCs were built from the working tree with no tag, signed with the release key, and posted
only on pgpony.app/rc/. Their source was on main, but nothing tied an RC APK to one commit, and a working-tree
build cannot be reproduced. A tester raised this in Oct 2026 (RC transparency), and it was right. The history of
the earlier RCs is in docs/RC_HISTORY.md.

Fill in `<X.Y.Z>` (the release, e.g. 4.7.2) and `<N>` (the RC number). The RC keeps the release's versionCode and
versionName; the tag and the asset names carry the RC number.

## 0. Before the first RC tag: F-Droid must ignore RC tags

The fdroiddata recipe for com.pgpony.android uses `UpdateCheckMode: Tags`, which considers every tag. An RC tag
would be built as the release (same versionCode), and the real release with that versionCode would then never be
picked up. The recipe must read:

```
UpdateCheckMode: Tags ^v[0-9]+\.[0-9]+\.[0-9]+$
```

Until that MR is merged, do not push a `-rc` tag. An RC in that window is built through the gate from a pushed
branch `rc/<X.Y.Z>-rc<N>` (the gate clones a branch the same way), and gets its tag and pre-release once the
recipe change is live.

## 1. Commit and tag

Stage by path. The commit message starts with `<X.Y.Z> RC<N>:`.

```
git commit -S -m "<X.Y.Z> RC<N>: <summary>"
git push origin main
git tag -s v<X.Y.Z>-rc<N> -m "PGPony <X.Y.Z> RC<N>"
git verify-tag v<X.Y.Z>-rc<N>
git push origin v<X.Y.Z>-rc<N>
```

## 2. Build through the gate

```
tools/verify_repro.sh rebuild v<X.Y.Z>-rc<N>
```

Then build the signed APK inside the gate's clean clone and compare it, exactly as in
REPRODUCIBLE_BUILDS_PLAYBOOK.md section 6 steps 3 and 4, with the output named
`/tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk`. The compare must print IDENTICAL and the certificate must be the release
certificate.

## 3. Sign and publish as a pre-release

```
gpg --detach-sign --armor --local-user 0x53F9798E4919DE62 --output /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk.asc /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk
gh release create v<X.Y.Z>-rc<N> --prerelease --draft --verify-tag --title "PGPony <X.Y.Z> RC<N>" --notes-file <notes> /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk /tmp/PGPony-<X.Y.Z>-RC<N>-foss.apk.asc /tmp/NorseHorse-release-key.asc /tmp/PGPony-<X.Y.Z>-RC<N>-signing-keys.txt
gh release edit v<X.Y.Z>-rc<N> --draft=false
```

The notes: what the RC is for (the issues it asks testers to check), the whole-file SHA-256 and the content
hash, the same "Verify this build" section as a release, and a line that this is a release candidate, not a
release. Pre-releases are immutable like releases. The in-app update check reads `releases/latest`, which
skips pre-releases, so no one is offered an RC.

## 4. Mirror on pgpony.app

Copy the same three files (APK, .asc, .sha256) to `/var/www/pgpony/rc/<X.Y.Z>-RC-foss/` with scp (the upload
portal is for releases only). The files must be the ones on the pre-release; check the live hash against it.

## 5. Announce

Link the GitHub pre-release in the issues it addresses, with the pgpony.app link as a mirror. It installs in
place over the GitHub and F-Droid builds (same key), not over Play.

## 6. Record

Add the RC to docs/RC_HISTORY.md: tag, commit, content hash, whole-file SHA-256.
