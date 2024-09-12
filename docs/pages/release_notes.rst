#############
Release notes
#############

*******************
Peanut (6.0.0)
*******************

**Release date:** TBD
**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.0...v6.0.0

================
Breaking changes
================

- Container user has changed from root to ``18081``. (see :ref:`running-docker`)
  When migrating from v5, change the owner of the data directory on the host to that of the container's user. (``chown -R 18081:18081 /path/to/host/data-dir``)
- Docker image tags have been changed: previously version tags had were prefixed with ``v`` (e.g., ``v5.0.0``), this prefix has been dropped to better adhere to industry standards.
- The VDR v1 ``createDID`` (``POST /internal/vdr/v1/did``) no longer supports the ``controller`` and ``selfControl`` fields. All did:nuts documents are now self controlled. All existing documents will be migrated to self controlled at startup.
- Removed legacy API authentication tokens.

============
New Features
============

The following new features have been added:

- Resolving and creating ``did:web`` DID documents (see the VDR v2 API reference for usage).
- Resolving ``did:jwk`` and ``did:key`` DID documents.
- Running a Discovery Server and Client (see :ref:`discovery`)
- Added the VDR v2 API.
- Added a Verifiable Credential system-wallet, which is used in Presentation Exchanges (e.g. OpenID4VP).
  See the VCR API reference for usage.
- Added a VCR API operation to list Verifiable Credentials in a local wallet.
- Added a VCR API operation to delete Verifiable Credentials from a local wallet.
- Added support in the ``IssueVC`` VCR API operation to issue Verifiable Credentials that don't use the ``nuts.nl`` JSON-LD context.
- Added experimental support for OpenID4VP (OpenID for Verifiable Presentations)
- Added experimental support for OpenID4VCI (OpenID for Verifiable Credential Issuance)
- Added support for Nuts RFC021, which negotiates an OAuth2 access token for a system through a Presentation Exchange using Verifiable Credentials.
- Added support for `StatusList2021 <https://www.w3.org/TR/2023/WD-vc-status-list-20230427/>`_ as revocation means for Verifiable Credentials.
- Added support for storage in SQL databases (PostgreSQL, MySQL, SQLite and Microsoft SQL Server, see :ref:`storage-configuration`) for various features.
- Added a Docker developer image (see :ref:`running-docker`) which is useful for local development. It is built from the latest ``master`` build.
- Added a VDR API operation to list locally managed DIDs.

=======
Changes
=======

- Removed support for deprecated network TLS properties. Configuring these properties will now cause the node not to start.
- Removed usage of deprecated ``purposeOfUseClaim`` in ``NutsAuthorizationCredential``.
- Removed support for the UZI authentication means.
- Documentation of ``did:nuts``-related features have been removed (refer to v5 documentation).
- Documentation of specific use cases (e.g. health care in general or eOverdracht) has been moved to the `Nuts wiki <https://wiki.nuts.nl>`_.
- Node can now be run without configuring TLS when the gRPC network isn't used (no bootstrap node configured and no network state), to cater use cases that don't use ``did:nuts``.

The following features have also been changed:

DID management
==============

You no longer manage changes to DIDs but to Subjects. Each subject has multiple DIDs, one for each enabled DID method.
You're free to choose an ID for a Subject. This feature enables forwards compatibility with new DID methods.
DID methods can be enabled and disabled via the ``vdr.didmethods`` config parameter. (Default: ``['web','nuts']``).
Existing ``did:nuts`` documents will be migrated to self-controlled at startup and the DID will be added as SubjectID.

HTTP interface
==============

The HTTP interface has been reworked to make deployments simpler and more secure:

- No more dynamic binding of endpoints to ports, endpoints are now bound to the internal interface (``8081``) or the public interface (``8080``).
- Server-side TLS for HTTP has been dropped, since the Nuts node is always expected to be deployed behind a reverse proxy/ingress that handles TLS termination.
- API authentication is now only applied to ``/internal`` endpoints, since those are the only API endpoints that should be protected with authentication.
- CORS support has been removed. As it is only required by user authentication endpoints that are considered to be deprecated, CORS headers can be set by a reverse proxy if still required.

Port configuration
------------------
To simplify HTTP configuration and proxying and make the default more secure, HTTP endpoints now map to 2 HTTP interfaces:

- port ``8081`` for all internal-facing endpoints (``/internal``, ``/status``, ``/metrics``, ``/health``)
- port ``8080`` for all public-facing endpoints (all others)

Note that ``8081`` by default maps to ``127.0.0.1`` only, so you might need to configure it to allow it to be accessible from other machines.

Deprecated features
===================

The following features have been deprecated:

- The external key store API has been deprecated and will be removed in the next major release.
  It was introduced to allow flexible support for other key storage backends, while reducing the number of dependencies and clients to maintain in the Nuts node.
  But, in practice the secret store API is unmaintained itself and lacks features (e.g. authentication/authorization).
  Starting v6, the preferred way to support other key storage backends is to directly implement it in the Nuts node itself.
  This also reduces the complexity of a Nuts node deployment (one service less to configure and deploy).
  Users are recommended to switch to the built-in client of their key storage backend.
- VDR v1 API.

************************
Hazelnut update (v5.4.9)
************************

Release date: 2024-08-09

- Disabled darkmode in UI for EmployeeID contract screen
- Clarified logging when existence of private key cannot be determined

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.8...v5.4.9

************************
Hazelnut update (v5.4.8)
************************

Release date: 2024-07-15

- Fixed a VC search bug where certain VCs could no longer be found.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.7...v5.4.8

************************
Hazelnut update (v5.4.7)
************************

Release date: 2024-05-30

- Fixed an issue where the node would panic during startup when retrying unfinished private transactions.
- Updated dependencies

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.6...v5.4.7

************************
Hazelnut update (v5.4.6)
************************

Release date: 2024-02-27

- VCR: lower log level for disallowed JSON-LD context URLs from 'error' to 'debug' (#2837)
- Updated dependencies

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.5...v5.4.6

************************
Hazelnut update (v5.4.5)
************************

Release date: 2023-12-11

- Auth: make sure create session and validate signatures perform the same checks (#2664)

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.4...v5.4.5

************************
Hazelnut update (v5.4.4)
************************

Release date: 2023-10-27

- Reduce repeated error logging of failed events

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.3...v5.4.4

************************
Hazelnut update (v5.4.3)
************************

Release date: 2023-09-07

- Fixed an issue where revocations received through the network were not written to a backup that was introduced in v5.4.0.
  Nodes upgrading from v5.4.0-v5.4.2 need to make an empty POST call to ``<node-address>/internal/network/v1/reprocess?type=application/ld+json%3Btype=revocation``.
- Reduced number of pages transmitted per message on a full sync to enhance performance
- Fixed a performance issue with initializing the backup databases
- Fixed some typos in NL language templates (@jelmerterwal)

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.2...v5.4.3

************************
Hazelnut update (v5.4.2)
************************

Release date: 2023-08-20

- Fixed issue where NutsEmployeeCredentials needed to be explicitly trusted when issued by another node

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.1...v5.4.2

************************
Hazelnut update (v5.4.1)
************************

Release date: 2023-07-24

Fixed versioning issue.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.4.0...v5.4.1

************************
Hazelnut update (v5.4.0)
************************

Release date: 2023-07-20

New features:

- Introduced support for issuing and receiving credentials over OpenID4VCI (OpenID Connect for Verifiable Credential Issuance).
  If the node's ``/n2n`` endpoint runs on port 443, the node will automatically configure its DIDs for OpenID4VCI support.
  If running on another port, additional action is required. See :ref:`openid4vci` for more information.
- Added certificate info to peer diagnostics.
- Added last connection error and the date/time of the next connection attempt to the network's address book.

Bug fixes/improvements:

- Diagnostics now shows correct number of owned conflicted DID document (``vdr.conflicted_did_documents.owned_count``).
- Added background job that periodically checks the node's network state and fixes incorrect XOR hashes.
  This can happen in certain high-load cases on Redis.
- Network peer authentication failures are now logged on debug instead of warn, leading to less chatter.
  To find out what error occurred, you should now look at the network's address book. /internal/network/v1/addressbook
- When creating new DID documents, the VDR now checks whether the specified controllers actually exist.
- Helm chart got updated (@henk-hofs-pink).

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.3.0...v5.4.0

************************
Hazelnut update (v5.3.2)
************************

Release date: 2023-08-20

- Fixed issue where NutsEmployeeCredentials needed to be explicitly trusted when issued by another node

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.3.1...v5.3.2

************************
Hazelnut update (v5.3.1)
************************

Release date: 2023-06-13

- Fixed issue where a Reprocess failed due to missing data

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.3.0...v5.3.1

************************
Hazelnut update (v5.3.0)
************************

Release date: 2023-05-26

- Automatically resolving of node DIDs has been removed, since it caused more confusion than it simplified things.
  It was only meant for workshop/demo purposes and not allowed in strict mode, so the impact should be very limited.
  If you didn't configure a node DID but do want to exchange private credentials,
  you now have to configure it explicitly using `network.nodedid`.
- The ``tls.crl.maxvaliditydays`` config flag has been deprecated. CRLs are now updated more frequently, making this option obsolete.
- Adds support for RFC019 and RFC020, which describe a new EmployeeIdentity authentication means which allows an employer to make claims
  about the identity of their employees. This has a lower level of assurance, but can be used when parties trust each others employee enrollment process.
- Fixed issue where VDR could no longer update broken DID Documents.
- Added API calls to _Didman_ to update endpoints and compound services (previously, they had to be deleted and then recreated to change them).
- NutsAuthorizationCredentials and NutsOrganizationCredentials now require a valid ``credentialSubject.id`` (meaning it is a DID).

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.2.0...v5.3.0

************************
Hazelnut update (v5.2.3)
************************

Release date: 2023-06-13

- Fixed issue where a Reprocess failed due to missing data

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.2.2...v5.2.3

************************
Hazelnut update (v5.2.2)
************************

Release date: 2023-05-16

- Fixed issue where VDR could no longer update broken DID Documents.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.2.1...v5.2.2

************************
Hazelnut update (v5.2.1)
************************

Release date: 2023-05-08

- A ```NutsOrganizationCredential``` with an invalid ```credentialSubject.id``` could cause Didman's ```SearchOrganizations```
  call to fail. This is now fixed by ignoring invalid credentials.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.2.0...v5.2.1

************************
Hazelnut update (v5.2.0)
************************

Release date: 2023-04-25

- Some VDR OpenAPI operations specified ``application/json+did-document`` as Content-Type, while they actually returned ``application/json``.
  This inconsistency is fixed by changing the OpenAPI specification to ``application/json``.
- Diagnostics now show the conflicted document count for DID Documents the node controls. See monitoring documentation for more detail.
- ``network.connections.outbound_connectors`` on ``/status/diagnostics`` has been moved to ``/internal/network/v1/addressbook``.
  Previously it showed only failing connections, now it shows all addresses it will try to connect to (regardless it's already connected to them or not).
- Added support for encrypting documents using the JWE standard (for DIDComm support).

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.1.0...v5.2.0

************************
Hazelnut update (v5.1.2)
************************

Release date: 2023-06-13

- Fixed issue where a Reprocess failed due to missing data

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.1.1...v5.1.2

************************
Hazelnut update (v5.1.1)
************************

Release date: 2023-05-16

- Fixed issue where VDR could no longer update broken DID Documents.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.1.0...v5.1.1

*************************
Hazelnut release (v5.1.0)
*************************

Release date: 2023-03-15

- Default value of strictmode changed to true.
- Introduced new HTTP-based crypto backend, which allows integration of other key storage backends.
  It uses a separate service (like a sidecar in Kubernetes) which implements a standardized API.
  The feature is still experimental, but will become the recommended backend for storing private keys in the next major release.
  See `Storage Configuration <https://nuts-node.readthedocs.io/en/latest/pages/deployment/storage-configuration.html#external-store-api>`_ for more information.
- Fixed situations in which parallel updates of a DID documents lead to the node not being able to process certain DID documents,
  leading to the node not being able to receive new transactions. This situation is recognizable by the following error:
  ``unable to verify transaction signature, can't resolve key by TX ref`` (note there are other cases this error can occur).
  This typically happened when one of the parallel updates removes keys from a DID document (e.g. deactivation).
- Internal storage of VDR has changed. A migration will run at startup. If the node is stopped during this process, DID Documents will have to be reprocessed manually (restore functionality)
- Added audit logging for cryptographic operations (creating a new key pair, signing, decrypting).
  Refer to the documentation for more information.
- Added new API authentication method, in which the administrator configures authorized public keys and the API client is responsible for signing JWT using the private key. This new API authentication is preferred over the current method, which will be removed in the next major release.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.0...v5.1.0

================
Breaking changes
================

There are no breaking changes, but if you're running in non-strict mode (but didn't actively disable it), you'll have to disable strict mode by setting ``strictmode`` to ``false``.

************************
Coconut update (v5.0.10)
************************

Release date: 2023-03-01

This patch release fixes the following:

- Drawing up an IRMA contract with an ampersand in the organization name causes the ampersand to be URL encoded,
  causing validation of the signed contract to fail.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.9...v5.0.10

***********************
Coconut update (v5.0.9)
***********************

Release date: 2023-02-21

This patch release fixes the following:

- Validations performed when revoking a VC are now more lenient: don't check whether it can actually find the VC in the issuer's database.
  Enables issuers to revoke VCs even if they've lost track of them (e.g. incorrect database backup/restore).

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.8...v5.0.9

***********************
Coconut update (v5.0.8)
***********************

Release date: 2023-02-09

This patch release fixes the following:

- A DID Document update could fail if a deactivation had occurred but was not referenced resulting in failed events

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.7...v5.0.8

***********************
Coconut update (v5.0.7)
***********************

Release date: 2023-02-01

This patch release fixes the following:

- Allow multiple incoming connections from the same IP

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.6...v5.0.7

***********************
Coconut update (v5.0.6)
***********************

Release date: 2023-01-24

This patch release fixes the following:

- Irma configuration not applied from config

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.5...v5.0.6

***********************
Coconut update (v5.0.5)
***********************

Release date: 2022-12-22

This patch release fixes the following:

- Full version tag in Docker Hub was missing prefix ``v``

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.4...v5.0.5

***********************
Coconut update (v5.0.4)
***********************

Release date: 2022-12-22

This patch release fixes the following:

- SearchVCs input is now validated against the provided JSON-LD context(s). This helps signalling faulty search queries.
- CRLs of expired certificates are no longer updated, and now don't cause blocking errors any more.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.3...v5.0.4

***********************
Coconut update (v5.0.3)
***********************

Release date: 2022-12-08

This patch release fixes the following:

- remove gcc and musl-dev deps
- VCR: Fix validator allowing localParameters

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.2...v5.0.3

***********************
Coconut update (v5.0.2)
***********************

Release date: 2022-11-30

This patch release fixes the following:

- Synchronize calls to DIDMan to avoid parallel calls from clients creating conflicted DID documents

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.1...v5.0.2

***********************
Coconut update (v5.0.1)
***********************

Release date: 2022-11-18

This patch release fixes the following:

- Redact secrets (e.g. ``crypto.vault.token``) in logging (e.g. at startup). They will now show up as ``(redacted)``.
- Fix half-downloaded IRMA schemas preventing the server to start. This happens when the node is shut down/crashes while downloading schemas.
  It now removes IRMA temporary directories which prevents the case from occurring.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v5.0.0...v5.0.1

*****************
Coconut (v5.0.0)
*****************

Release date: 2022-11-08

- HTTPS TLS offloading is now also possible at the Nuts node. Checkout the docs on TLS offloading for the details.
  By default this is turned off which corresponds to the current behaviour.
- Issuing a Verifiable Credential will now fail when it includes a property not defined in its JSON-LD context(s).
  The behavior was changed because undefined fields are not secured by the JSON-LD proof,
  which allows an attacker to alter it while the developer assumes it is secured by the signature.
  It also helps developers noticing they misspelled a property, which it previously accepted but may have caused issues at processing systems downstream.
- Redis Sentinel is now configured through configuration parameters, rather than via the Redis connection URL as introduced in v4.
  This is done to improve documentation and reduce complexity.
- Searching VCs (using REST API) now requires a wildcard to do a partial (prefix) search on strings.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.0.0...v5.0.0

================
Breaking changes
================

**NutsAuthorizationCredential LegalBase**
When issuing Verifiable Credentials, now all fields must be defined in its context(s). This impacts the issuance of NutsAuthorizationCredentials:
Nuts RFC014 (Authorization Credential) required ``legalBase`` to be present in all ``NutsAuthorizationCredential``\s,
but this property was missing in the Nuts v1 JSON-LD context.
Since it can't simply be added afterwards, it (``legalBase``) is removed altogether.
This means, starting this version, the ``legalBase`` property can't used in new v1 ``NutsAuthorizationCredential``\s.

**Redis Sentinel**
Redis Sentinel was configured through a Redis connection URL by passing Sentinel-specific query parameters,
which has been replaced with structured configuration. To use Redis Sentinel in v5 move the following connection URL parameters to configuration:

- ``sentinelMasterName`` becomes ``storage.redis.sentinel.master``
- comma-separated Sentinel hosts become a list of hosts as ``storage.redis.sentinel.nodes``
  If using a Redis connection URL, its host won't be used set, so set the host to any irrelevant value.
- ``sentinelUsername`` becomes ``storage.redis.sentinel.username``
- ``sentinelPassword`` becomes ``storage.redis.sentinel.password``

**Searching VCs**
Before v5, searching for VCs would use partial (prefix) matching for strings by default.
Starting v5 it will use exact matching on strings by default. To match on a prefix (string starting with a specific value), add an asterisk (``*``) at the end of the string.
To match for a non-nil string, use just an asterisk (``*``) meaning anything will match (but it must be present).

***********************
Coconut update (v4.3.1)
***********************

Release date: 2022-11-30

This patch release fixes the following:

- Synchronize calls to DIDMan to avoid parallel calls from clients creating conflicted DID documents

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.3.0...v4.3.1

************************
Chestnut update (v4.3.0)
************************

Release date: 2022-10-27

This update adds forward compatibility with the upcoming v5 release.
It removes validation of ``legalBase`` from ``NutsAuthorizationCredential``, which was never properly defined in the JSON-LD contexts.
The upcoming v5 release will refuse to issue credentials with fields that were not defined in the credential's context.
But, since ``legalBase`` is required up until v4.3.0, it would mean future ``NutsAuthorizationCredentials`` issued by upcoming v5 can't be used in v4.
Hence, the removal of the validation, to become forwards compatible with v5.

See https://github.com/nuts-foundation/nuts-node/issues/1580 for more information

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.2.4...v4.3.0

************************
Chestnut update (v4.2.4)
************************

Release date: 2022-09-29

Set IRMA to production mode when the Nuts node is in strict-mode.
This allows an IRMA app in non-developers-mode to connect to the Nuts node.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.2.3...v4.2.4

************************
Chestnut update (v4.2.3)
************************

Release date: 2022-09-21

Bugfix for Hashicorp Vault key store backend: stacktrace on missing key

Bugfix VAULT_TOKEN gets overwritten with empty default

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.2.2...v4.2.3

************************
Chestnut update (v4.2.2)
************************

Release date: 2022-08-31

Bugfix for Redis: not being able to load state data from database.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.2.0...v4.2.2

************************
Chestnut update (v4.2.0)
************************

Release date: 2022-08-29

Backports upstream features for connecting to Redis over TLS.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.1.1...v4.2.0

************************
Chestnut update (v4.1.1)
************************

Release date: 2022-08-18

This patch adds TLS offloading for gRPC connections with support for DER encoded client certificates.
This is required for supporting TLS offloading on HAProxy.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.1.0...v4.1.1

************************
Chestnut update (v4.1.0)
************************

Release date: 2022-08-04

This minor release adds TLS offloading for gRPC connections.

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v4.0.0...v4.1.0

*****************
Chestnut (v4.0.0)
*****************

Release date: 2022-07-22

This release introduces a pluggable storage system and support for:

* BBolt backups
* Experimental Redis support

**Full Changelog**: https://github.com/nuts-foundation/nuts-node/compare/v3.0.0...v4.0.0

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
Any party using these features will have until next version to migrate to the alternative.
Keep an eye on this section for every release.

- VCR V1 API is deprecated and will be removed in the next release. Please migrate all calls to the V2 API.

========
Bugfixes
========

This section contains a list of bugfixes. It'll match resolved Github issues with the **bug** tag.
