# Collaborating on nuts-node

Thanks for your interest in contributing. This file is the short version of
how we work. For security issues, see [SECURITY.md](SECURITY.md) — please do
not file vulnerabilities as public issues or PRs.

## Before you start

- **Open an issue first** for anything non-trivial (new feature, behaviour
  change, refactor that touches multiple packages). A 5-minute discussion
  up front beats a rejected PR.
- For typos, doc fixes, and obvious bugs, skip straight to a PR.

## Pull requests

### Keep them small

One concern per PR. A reviewer should be able to load the whole diff in their
head in a few minutes. Don't bundle refactors, renames, or "while I'm here"
cleanups with a feature or fix — land them as separate PRs.

### Sign your commits

All commits must be signed (GPG, SSH, or S/MIME). Branch protection
enforces this; unsigned commits cannot be merged. See
[git's documentation on signing](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
or [GitHub's setup guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

### Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>
```

Examples from recent history:

- `feat(crypto): accept RS256 in SupportedAlgorithms`
- `fix(auth/iam): enforce single authorization_details entry per call`
- `docs(auth/openid4vci): note follow-up to move URL validation to HTTPClient`
- `ci: move Go test pipeline from CircleCI to GitHub Actions`

Common types: `feat`, `fix`, `refactor`, `docs`, `test`, `ci`, `chore`.

Subjects are imperative ("add X", not "added X") and under ~72 chars. Put
the *why* in the PR description, not the commit message.

## Code

- **Match the surrounding code.** Naming, error handling, logging, test
  style — follow the nearest neighbour (same file > same package > repo).
  Don't introduce a new pattern when an existing one fits.
- **No drive-by refactors.** See "Keep them small" above.

## Tests

- New code needs tests. Bug fixes need a regression test that fails before
  the fix.
- Run the full suite before pushing: `go test ./...`.
- Integration / e2e tests live under `e2e-tests/`.

## Code generation

When you change OpenAPI specs, mock interfaces, or other generated inputs,
regenerate via the `makefile` — don't invoke `oapi-codegen` / `mockgen`
directly:

- `make gen-api`
- `make gen-mocks`
- `make run-generators`

## Review

- A maintainer from [`.github/CODEOWNERS`](.github/CODEOWNERS) needs to
  approve before merge.
- CI must be green. Don't merge with red checks.
- Address review comments by pushing additional commits.
- **Do not rebase or force-push once review has started.** It throws away
  GitHub's diff-since-last-review and forces reviewers to start over. Save
  the rebase/squash for the merge.

## Licence

By contributing you agree your changes are licensed under the same terms as
the project (see [COPYING](COPYING)).
