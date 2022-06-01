
#############
Release notes
#############

Whats has been changed, and how to update between versions.

***************
Cashew (v3.0.0)
***************

Release date: 2022-06-01

This release no longer contains the V1 network protocol.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v2.0.0...v3.0.0

***************
Brazil (v2.0.0)
***************

Release date: 2022-04-29

This version implements the V2 network protocol. The V2 network protocol combines gossip style messages with a fast reconciliation protocol for larger difference sets.
The protocol can quickly identify hundreds of missing transactions.
The new protocol is much faster than the old protocol and its performance is currently limited by the database performance.

Besides the improved network protocol, this version also implements semantic searching for Verifiable Credentials.
Till this version, searching for VCs only supported the NutsOrganizationCredential and NutsAuthorizationCredential. With the new semantic search capabilities all kinds of credentials can be issued and found.
This is the first step for the Nuts node to become a toolbox that supports multiple domains.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v1.0.0...v2.0.0

***************
Almond (v1.0.0)
***************

Release date: 2022-04-01

This is the initial release of the Nuts node reference implementation.
It implements RFC001 - RFC016 specified by the `Nuts specification <https://nuts-foundation.gitbook.io>`_.
This release is intended for developers. It contains a stable API that will be backwards compatible for the next versions.
The releases until the first production release will mainly focus on network and Ops related features.

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

- VCR V1 API is deprecated and will be removed in the next release. Please migrate all calls to the V2 API.

========
Bugfixes
========

This section contains a list of bugfixes. It'll match resolved Github issues with the **bug** tag.
