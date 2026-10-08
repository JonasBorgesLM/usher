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

- The release commit is the **last** thing merged into `develop` before the
  tag. Do not tag a commit on `main` that `develop` has already moved past —
  the merge-back step below would then have something real to reconcile,
  instead of being the no-op it is every other time.
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
git tag -v v0.1.0
```

## The `develop` → `main` merge

CONTRIBUTING.md's Git flow section already covers the steady state: every
merge into `develop` is immediately fast-forwarded into `main`, so by the
time a release is cut, **`main` already equals `develop`** — there is no
separate "merge develop into main" step left to perform. The tag is cut
directly on `main` at that shared commit:

```bash
git checkout main
git pull --ff-only origin main
git tag -a v0.1.0 -m "v0.1.0 — $(date -u +%Y-%m-%d): MVP acceptance (REQUIREMENTS §13) met"
git push origin v0.1.0
```

If `main` and `develop` have ever diverged by the time this is read, that is
itself a defect in the fast-forward discipline — fix `main` first (fast-
forward it to `develop`, or find out why it cannot be) rather than tagging a
commit `develop` has moved past.

## The merge back

CONTRIBUTING.md's own reasoning: release commits edit the files a release
exists to change (this document's own future edits, `SECURITY.md`'s
"Supported versions" line below, a version string if one is ever added), and
without merging back, `develop` and `main` diverge in exactly those files.

Because this project fast-forwards `main` from `develop` on every merge
rather than merging `develop` into `main` as a merge commit, **the tag itself
is the only thing `main` ever has that `develop` does not** — a tag is a ref,
not a commit, so there is nothing for `develop` to merge back. The step still
exists for the day a hotfix lands directly on `main` (which this project's
own flow does not do today, but a future one might): that commit, and only
that one, gets merged back into `develop` before the next release. Record
here, not re-derive each time: as of `v0.1.0`, this has never happened, and
the "merge back" is a check (`git merge-base --is-ancestor main develop`)
confirming it remains unnecessary, not an operation.

## After tagging

- Update `SECURITY.md`'s "Supported versions" section: `v0.1.0` is now the
  latest tag receiving fixes.
- `gh release create v0.1.0 --title v0.1.0 --generate-notes` — a GitHub
  Release is not what `#55`'s own done-when requires (that is the tag
  alone), but a tag with no release page is easy to miss from the repository
  front page.
- Confirm private vulnerability reporting is still on (`Settings → Security
  → Private vulnerability reporting`, or
  `gh api repos/<owner>/<repo>/private-vulnerability-reporting`) — `SECURITY.md`
  names it as the only reporting channel, so a toggle silently reverted
  elsewhere would make that document false.
