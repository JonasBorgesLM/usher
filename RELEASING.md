# Releasing

Who can read this and why it is short: there is one person cutting releases
today, and the steps below are the ones that are easy to get backwards under
pressure — not a general primer on `git tag`. CONTRIBUTING.md's own Git flow
section states the branch model this document assumes; read that first if
the `develop`/`main` relationship is unfamiliar.

## What freezes

Nothing is declared "code frozen" in the sense of blocking unrelated work —
this is a single-maintainer project, and a freeze exists to protect against
other people's concurrent merges, which do not happen here. What actually
matters:

- The release PR (`develop` → `main`, below) is opened from the `develop`
  commit that was verified. Anything merged into `develop` after it is opened
  waits for the next release — either close and reopen the PR, or let it
  ride; never tag a `main` commit whose contents were not the ones verified.
- REQUIREMENTS §13's own MVP acceptance is re-verified **on the commit being
  tagged**, not on a memory of when it last passed. §10's test suite,
  `scripts/probe-threats.sh`, and the `warden`/`sapper` reports under
  `docs/security/` are the evidence; re-run what a schema or dependency
  change since their last run could have invalidated.

## Tag signing

Already configured, not a step to perform: `tag.gpgsign=true` and
`gpg.format=ssh` are set in this machine's git config, with the same SSH key
commits already sign with (`user.signingkey`). An annotated tag
(`git tag -a`) is signed automatically — there is no separate `-s` flag to
remember, and forgetting `-a` is the actual failure mode (`git tag v0.1.0`
alone creates a lightweight, unsigned tag silently).

Verify a tag signed correctly after creating it:

```bash
git tag -v vX.Y.Z
```

## The `develop` → `main` merge

`main` holds released states only (CONTRIBUTING.md). Both branches require a
pull request and the `CI OK` check, so a release is a pull request too:

```bash
gh pr create --base main --head develop --title "chore: release vX.Y.Z" \
  --body "Release vX.Y.Z. Verified on <develop sha>: <what was re-run>."
```

Merge it with a **merge commit**, not a squash: the commits on `develop` are
each one subject, and a squash would leave `main` with history `develop` does
not share. Then tag the merge commit:

```bash
git checkout main
git pull --ff-only origin main
git tag -a vX.Y.Z -m "vX.Y.Z — $(date -u +%Y-%m-%d): <one line on what it carries>"
git tag -v vX.Y.Z
git push origin vX.Y.Z
```

**How `v0.1.0` was different, kept so the history reads correctly:** until the
first tag, `main` was fast-forwarded to `develop` after every merge, so
`v0.1.0` was tagged on a commit both branches already shared, with no release
PR. That rule ended at `v0.1.0`; the commits merged into `develop` after it
(#116 among them) only reach `main` through the next release PR.

## The merge back

The release merge commit exists only on `main`, but its tree is exactly
`develop`'s at that commit — there is nothing in it to bring back. So right
after tagging, the merge back is a check, not an operation:

```bash
git fetch origin
git diff --stat origin/develop origin/main   # empty: nothing to merge back
```

It stops being empty only if something was committed to `main` directly (a
hotfix, which this flow does not do today). In that case, open a PR from
`main` into `develop` for exactly those commits before anything else merges
into `develop`.

## After tagging

- `SECURITY.md`'s "Supported versions" line says "the latest tag receives
  fixes" and needs no edit per release; check it still reads true.
- `gh release create vX.Y.Z --title vX.Y.Z --generate-notes` — a tag with no
  release page is easy to miss from the repository front page.
- Close the milestones the release completes, so the open ones are only
  work still to do.
- Confirm private vulnerability reporting is still on (`Settings → Security
  → Private vulnerability reporting`, or
  `gh api repos/<owner>/<repo>/private-vulnerability-reporting`) — `SECURITY.md`
  names it as the only reporting channel, so a toggle silently reverted
  elsewhere would make that document false.
