.. _releasing-nuts-node:

Releasing Nuts Node
###################

Semantic versioning
*******************

Nuts Node and auxiliary tools/applications follow a semantic versioning scheme (``<major>.<minor>.<patch>(-rc.<rc>)``):

|   Given a version number MAJOR.MINOR.PATCH, increment the:
|
|    1. MAJOR version when you make incompatible API changes,
|    2. MINOR version when you add functionality in a backwards compatible manner, or
|    3. PATCH version when you make backwards compatible bug fixes.

(Taken from `semver.org <https://semver.org/>`_)

    Note: "API" is a broad term, it covers every interface interacted with by applications or other nodes (including Nuts network protocols).

When a new minor or major version is released, always create a release candidate first: ``<major>.<minor>.0-rc.1``, eg: ``v5.1.0-rc.1``.
This version will symbolize a feature freeze and will be used for the first tests.
All problems will be fixed and the release candidate version is increased on every bugfix release, eg: ``v5.1.0-rc.2``.
When no more problems are found the major/minor version is released without a ``-rc.<rc>`` postfix.
This approach prevents the docker ``latest`` tags to be updated to a new version automatically.

Aside from the Nuts Node itself, all projects that follow the same versions need to be released.
They follow the major version from the Nuts Node, but minor and patch versions may differ.

Major release
*************

A major release starts with version number ``<major>.0.0``. Every Nuts Node release has a name (e.g. "Brazil") and a version number.
A release consists of a Git tag and a release in Github with release notes. Releases are created according to the following format:

- Git tag: ``v<major>.<minor>.<patch>``, e.g. ``v2.0.0``
- Release name: ``<name> release (<version>)``, e.g.: ``Brazil release (v2.0.0)`` (every release has a designated name)
- Release notes: auto-generated by Github.

Bugfix release/patches
**********************

When an issue is fixed in a released version a bugfix/patch version must be released.
The bug must be fixed on a branch named after the major version, e.g. ``v1`` or ``v2``.
The release name follows the release name, but is named "bugfix" instead of "release". E.g.: ``Brazil bugfix (v2.0.1)``.

Backports
^^^^^^^^^

Bugfixes often need to be backported, e.g. it's fixed on the ``master`` branch but also need to be fixed in the last version,
and maybe even in the before last version. Bugfix releases stemming from backports follow the same versioning and naming scheme as regular bugfix releases.

Building a release
******************

Make sure all changes are on the relevant branch.
If it's for an older version (backport), cherry-pick all changes that need to be included and merge them into be the correct branch (e.g., V5.4, V6.1).
Make sure to add the release notes to the branch *before* tagging a release or it will not be visible on read-the-docs.
For good measure, also run ``make cli-docs`` (requires ``rst_include`` python package to be installed) to make sure we didn't forget to update the documentation.

Go to `releases on github <https://github.com/nuts-foundation/nuts-node/releases>`_ and perform the following steps:

#. ``Draft new release``
#. set the target branch
#. ``Choose a tag`` and create a new one according to git tag convention above (e.g. v6.1.0)
#. ``Generate release notes``
#. (optional) curate release text. For major/minor versions probably replace with the release notes written for read the docs.
#. Set the ``Set as latest release`` checkbox as needed
#. ``Publish release``

This will trigger github actions that publish a new release to `Docker Hub <https://hub.docker.com/r/nutsfoundation/nuts-node/tags>`_, and a message will be posted in ``#releases`` channel on Slack.

Major/Minor version updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Make a new branch**

Every new major or minor version has its own branch.
After creating a new release, a new branch should be made based off of the git tag for the release.
The naming convention for branches is ``V<major>.<minor>``, e.g. V6.0 or V5.4. (Yes git/github tag/version uses lowercase ``v``, branches use uppercase ``V``, and Docker tags omit the prefix entirely since version 6.0)
Add branch protection to the new branch on Github.

**read the docs**

Go to `app.readthedocs.org/projects/nuts-node <https://app.readthedocs.org/projects/nuts-node/>`_ and click on ``+ Add version`` to add the new branch to the available documentation versions on `nuts-node.readthedocs.io <https://nuts-node.readthedocs.io/>`_.

**Automated tests**

Testing is automated using Github workflows.
Some of the tests cannot handle branch patterns and require updating relevant major/minor version branches to the workflow file manually.
The current list of files that need to be updated are:

- **Scheduled govulncheck** action: ``.github/workflows/govulncheck-cron-schedule.yaml``. Runs every day and sends vulnerability warnings to the ``#nuts-core-team`` slack channel.
- **Scheduled CodeQL** action: ``.github/workflows/codeql-analyisis-cron-schedule.yaml``
