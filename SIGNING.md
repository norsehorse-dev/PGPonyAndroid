# Signing commits and tags

Commits on main and release tags are signed with the norsehorse-dev SSH
signing key (#81). The public key, and how anyone can verify with it, is in
the README under Verify a release.

## What signs automatically

On the Mac, the global git config signs every commit and tag:

```
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/norsehorse_signing.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

So a commit or a `git tag` made on the Mac is signed with no extra step.

The settings live in the global config on purpose, not in this repository's
`.git/config`. Commits made from a shell that cannot reach the key (an
automated session working on this folder, for example) would fail outright if
the repository itself required signing. Those commits are made unsigned and
signed on the Mac before they are pushed.

## Before every push

Sign anything not yet pushed, check it, then push:

```
git rebase --autostash --force-rebase --gpg-sign origin/main
git log --show-signature origin/main..HEAD
git push
```

`--autostash` sets uncommitted work aside for the rebase and puts it back
afterwards, so changes in progress (Play listing, screenshots) can stay
uncommitted. Every commit listed must show `Good "git" signature`. The rebase only
rewrites commits that are not on origin yet, so it is safe to run every time;
with nothing to push it does nothing.

Never run it on commits that are already pushed.

A contributor's pull request is the exception. Their commits are theirs and
stay unsigned; merge them with a signed merge commit (`git merge --no-ff -S`)
and never run the rebase above over them, since it would re-sign them as
norsehorse-dev, flatten the merge and move any tag already pushed on top. Check
that only the contributor's commits are unsigned, then push past the hook:

```
git log --format='%h %G? %an %s' origin/main..HEAD
git push --no-verify origin main
```

4.8.0 RC6 merged #95 this way (merge d4a972c).

A pre-push hook enforces this: it refuses a push while any commit in it is
unsigned, and prints the rebase command. Install it once per clone:

```
cp tools/hooks/pre-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

## Release tags

`git tag v<version>` signs because of `tag.gpgsign`. Check before pushing the
tag:

```
git verify-tag v<version>
git push origin v<version>
```

## The key

- Private key: `~/.ssh/norsehorse_signing` on the Mac, used only for signing.
- Public key: `~/.ssh/norsehorse_signing.pub`, registered on the
  norsehorse-dev GitHub account as a signing key (not a login key), and
  printed in the README.
- If the key is ever replaced, add the new one on GitHub as a signing key,
  update the README and `~/.ssh/allowed_signers`, and keep the old public key
  listed in the README so older tags still verify.
