Sync release notes from a release branch to master. The argument is the release version (e.g., `v5.4.26`).

Steps:
1. Derive the release branch name from the version (e.g., `v5.4.26` → branch `V5.4`).
2. Run `git fetch origin` to ensure the remote branches and tags are up to date.
3. Compare the release notes to find what is missing in master:
   ```
   git diff master:docs/pages/release_notes.rst <release-branch>:docs/pages/release_notes.rst
   ```
4. Read the release notes from the release branch to get the exact content to add:
   ```
   git show <release-branch>:docs/pages/release_notes.rst
   ```
5. Edit `docs/pages/release_notes.rst` on master to insert the new release section(s) in reverse-chronological order:
   - v6.x sections come before v5.x sections
   - Within v5.x, newer versions come first
   - Each section uses this RST format (asterisk count must match title length exactly):
     ```
     *************************
     Hazelnut update (v5.4.X)
     *************************

     Release date: YYYY-MM-DD

     - Change description

     **Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/vX.Y.Z-1...vX.Y.Z
     ```
6. Use `report_progress` to commit with message `docs: add <version> release notes` and push.
7. Create a pull request targeting `master`:
   - Title: `docs: add <version> release notes to master`
   - Body:
     ```
     This PR adds the <version> release notes to master.

     ## Changes
     - Added release notes for <version> (released YYYY-MM-DD)

     ## Release highlights
     - <highlight 1>
     - <highlight 2>
     ```
