# Maintainer's Guide

This guide contains processes and procedures for maintaining the nuts-node repository.

## Table of Contents
- [Syncing Release Notes from Release Branch to Master](#syncing-release-notes-from-release-branch-to-master)

---

## Syncing Release Notes from Release Branch to Master

When a new release is created on a release branch (e.g., `V5.4`), the release notes need to be synced to the `master` branch to keep the documentation complete.

### Process

1. **Identify what's missing**
   
   Compare the release notes between the release branch and master to see what needs to be added:
   ```bash
   git diff master:docs/pages/release_notes.rst V5.4:docs/pages/release_notes.rst
   ```

2. **Create a new branch from master**
   
   ```bash
   git checkout master
   git pull
   git checkout -b merge-vX.Y-release-notes
   ```

3. **Extract the new release notes**
   
   View the release notes from the release branch to identify what needs to be added:
   ```bash
   git show V5.4:docs/pages/release_notes.rst | head -20
   ```

4. **Edit the release notes file**
   
   Open `docs/pages/release_notes.rst` and insert the new release section(s) in the correct chronological position:
   - New releases should appear after the latest v6.x releases (if the release is v5.x)
   - Maintain the existing format and structure
   - Ensure proper RST formatting with the correct number of asterisks for section headers

5. **Commit and push the changes**
   
   ```bash
   git add docs/pages/release_notes.rst
   git commit -m "docs: add vX.Y.Z release notes"
   git push -u origin merge-vX.Y-release-notes
   ```

6. **Create a Pull Request using GitHub CLI**
   
   ```bash
   gh pr create \
     --base master \
     --head merge-vX.Y-release-notes \
     --title "docs: add vX.Y.Z release notes to master" \
     --body "This PR adds the vX.Y.Z release notes to master.

   ## Changes
   - Added release notes for vX.Y.Z (released YYYY-MM-DD)

   ## Release highlights
   - Feature/fix 1
   - Feature/fix 2"
   ```

### Example

For adding v5.4.26 release notes:

```bash
# 1. Check what's different
git diff master:docs/pages/release_notes.rst V5.4:docs/pages/release_notes.rst | head -50

# 2. Create branch
git checkout master && git pull
git checkout -b merge-v5.4-release-notes

# 3. View the new release notes
git show V5.4:docs/pages/release_notes.rst | head -16

# 4. Edit docs/pages/release_notes.rst
# Insert the v5.4.26 section before v5.4.25

# 5. Commit and push
git add docs/pages/release_notes.rst
git commit -m "docs: add v5.4.26 release notes"
git push -u origin merge-v5.4-release-notes

# 6. Create PR
gh pr create \
  --base master \
  --head merge-v5.4-release-notes \
  --title "docs: add v5.4.26 release notes to master" \
  --body "This PR adds the v5.4.26 release notes to master..."
```

### Tips

- The release notes file follows reverse chronological order (newest first)
- V6.x releases appear before V5.x releases in the master branch
- Each release section uses the format:
  ```rst
  *************************
  Hazelnut update (v5.4.X)
  *************************
  
  Release date: YYYY-MM-DD
  
  - Change description
  
  **Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/vX.Y.Z-1...vX.Y.Z
  ```
- Always verify the correct number of asterisks matches the title length in RST format
- Test locally if possible before creating the PR

### Troubleshooting

**Problem**: `gh pr create` fails with "No commits between master and branch"

**Solution**: Make sure you've committed your changes. The branch must have commits that differ from master.

**Problem**: PR shows conflicts

**Solution**: Make sure you created your branch from the latest master and that you're inserting the release notes in the correct location (chronologically).

