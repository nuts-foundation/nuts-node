---
name: dependabot-merge
description: Use this skill when the user asks to process, approve, or merge dependabot PRs, or asks to do "dependabot-merge".
disable-model-invocation: true
allowed-tools: Bash(gh pr list:*), Bash(gh pr review:*), Bash(gh pr merge:*), Bash(gh pr view:*)
---

## Open Dependabot PRs

!`gh pr list --author "app/dependabot" --state open --json number,title,url,statusCheckRollup`

## Your task

For each open dependabot PR above:

1. **Check CI**: A PR passes if every check has conclusion `SUCCESS`, `NEUTRAL`, or `SKIPPED` (none are `FAILURE` or still pending). Skip failing/pending PRs and report them at the end.

2. **Risk assessment**: Fetch the PR body with `gh pr view <number>` to read the release notes / changelog link. Assess whether the update could be breaking:
   - Major version bumps are high risk
   - Minor version bumps may introduce behavior changes — check the changelog if available
   - Patch version bumps are generally safe
   - Security-sensitive packages (auth, crypto, TLS, HTTP) warrant extra caution regardless of version
   - If the release notes mention breaking changes

3. **Analyze**: Given the release notes, check if we need to update code.

4. **Decide**:
   - If the update looks safe: approve (`gh pr review <number> --approve`) and squash-merge (`gh pr merge <number> --squash`).
   - If the update looks risky or unclear: **stop and ask the user** before proceeding. Explain what the concern is.

5. At the end, report a summary: what was merged, what was skipped due to CI failure, and what was flagged for user review.

Do this one-by-one.
