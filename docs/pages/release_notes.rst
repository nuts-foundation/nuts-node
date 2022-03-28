
#############
Release notes
#############

Whats has been changed, and how to update between versions.

***************
Almond (v1.0.0)
***************

Release date: 2022-04-01

This is the initial release of the Nuts node reference implementation.
It implements RFC001 - RFC017 specified at the `Nuts specification <https://nuts-foundation.gitbook.io>`_.
This release is intended for developers. It contains a stable API that will be backwards compatible for the next versions.
The releases until the first production release will mainly focus on network and OPS related features.

To start using this release, please consult the getting started section.

=======================
Features / improvements
=======================

Future releases will list new features and improvements that have been added since the previous release.

================
Dropped features
================

New major releases might drop support for features that have been deprecated in a previous release.
Keep an eye on this section for every release.

===================
Deprecated features
===================

Some features will be deprecated because they have been succeeded by an improved version or when they are no longer used.
Removing old code helps in reducing maintenance costs of the code base.
Features that are marked as *deprecated* will be listed here.
Any vendor using these features will have until next version to migrate to the alternative.
Keep an eye on this section for every release.

- VCR V1 API is deprecated. Please migrate all calls to the V2 API.

========
Bugfixes
========

This section contains a list of bugfixes. It'll match resolved Github issues with the **bug** tag.
