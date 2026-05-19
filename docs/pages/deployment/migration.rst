.. _nuts-node-migration:
.. _nuts-node-migrations:

Migrating from v5 to v6
************************

This guide is an upgrade runbook for operators moving an existing v5 deployment to v6.
It covers the operational changes that affect a running node on first start, in addition to the on-startup DID document migrations.
Topics that already have a dedicated page (storage, recommended deployment, API authentication) are linked rather than duplicated.

Recommended order:

1. Work through `Before you upgrade`_.
2. Apply the `Deployment changes`_ to your host, container, and reverse proxy configuration.
3. Start the v6 node and let the `Startup migrations`_ run.
4. Run the checks in `Validating a migrated node`_ before cutting traffic over.

.. contents::
    :local:
    :depth: 2

Before you upgrade
==================

Resolve DID document conflicts
------------------------------

Conflicted ``did:nuts`` documents migrate as the resolved (merged) state, which can differ from the published history.
Resolve all conflicts on v5 before starting v6.

- Check ``/status/diagnostics`` for the count of owned conflicted DIDs.
- If non-zero, list them via ``/internal/vdr/v1/did/conflicted`` and resolve each one on v5.

Provision an SQL database
-------------------------

v6 requires SQL storage. The following all live in SQL and cannot be disabled:

- Subjects and their DID-method bindings
- ``did:web`` document management
- The credential wallet
- The discovery service
- OpenID4VP and OpenID4VCI sessions
- The crypto ``key_reference`` table that links KIDs to backend key names

Supported engines: PostgreSQL, MySQL, Microsoft SQL Server, Azure SQL, and SQLite.
SQLite is acceptable for small or single-node deployments; production deployments should use a server-based engine.
See :ref:`storage-configuration` for connection strings, RDS IAM, and other engine-specific options.

Choose enabled DID methods
--------------------------

The ``didmethods`` config parameter (default ``["web","nuts"]``) controls which DID methods the node enables and which startup migrations run.

- v5 deployments that only use ``did:nuts``: set ``didmethods = ["nuts"]``. The node skips the ``did:web`` migration.
- v5 deployments that plan to adopt ``did:web``: keep both enabled. The startup migration adds a ``did:web`` document alongside each existing ``did:nuts`` subject.
- Greenfield ``did:web`` deployments: set ``didmethods = ["web"]``. None of the v5 startup migrations apply.

Stop using VDR v1 if the subject has more than one DID
------------------------------------------------------

This is a one-way upgrade decision; make it before you start v6.

VDR v1 writes (including service management on ``did:nuts``) only touch the ``did:nuts`` document.
They are **not** propagated to other DIDs in the same subject.
On the default ``didmethods = ["web","nuts"]``, the ``did:web`` document silently drifts out of sync with ``did:nuts`` every time a VDR v1 write lands.

Pick one of:

- **Keep using VDR v1** — set ``didmethods = ["nuts"]`` so each subject contains exactly one DID and there is nothing to drift against. You forgo ``did:web`` for now.
- **Move to VDR v2** — keep the default ``didmethods`` (or any multi-method config) and migrate all service / DID management to the VDR v2 API. v2 operates on the subject and updates every enabled DID method atomically.

There is no safe middle ground: running multi-method subjects while still issuing VDR v1 writes will produce divergent DID documents that the migrations cannot reconcile on a later restart.

Deployment changes
==================

HTTP interface split
--------------------

v6 binds HTTP endpoints to two interfaces with fixed routing — endpoints no longer move between ports based on configuration.

- ``:8080`` (``http.public.address``) — public-facing endpoints (e.g. ``/iam``, ``/oauth2``, ``/n2n``, ``/.well-known``).
- ``127.0.0.1:8081`` (``http.internal.address``) — ``/internal``, ``/status``, ``/metrics``, ``/health``.

The internal interface defaults to loopback. To expose it to other hosts (for example to a metrics scraper on another node), set ``http.internal.address`` to ``:8081`` or to a specific interface address, and restrict access at the network layer.

Reverse proxy and TLS
---------------------

Server-side TLS for HTTP has been removed. Operators must terminate TLS in a reverse proxy or ingress in front of the node.

- Public endpoints on ``:8080`` need a publicly trusted certificate.
- Internal endpoints on ``:8081`` should not be reachable from the internet.
- See :ref:`nuts-node-recommended-deployment` for a reference topology.

If ``didmethods`` does not contain ``nuts``, the gRPC network is not started and the node can run without any TLS configuration at all.

Container user and image tags
-----------------------------

- The container runs as UID ``18081`` instead of ``root``. Before starting v6, take ownership of the host data directory: ``chown -R 18081:18081 /path/to/host/data-dir``. See :ref:`running-docker`.
- Docker image tags no longer carry the ``v`` prefix: ``v5.0.0`` → ``6.0.0``. Update your image references; otherwise pulls silently fail to find the v6 tag.

Removed and renamed config keys
-------------------------------

Apply the following changes to your config file or environment variables before starting v6:

.. list-table::
    :header-rows: 1
    :widths: 30 30 40

    * - v5 key
      - v6 replacement
      - Notes
    * - ``auth.publicURL``
      - ``url``
      - Removed. ``url`` now covers the public URL requirement (including Yivi).
    * - IRMA/Yivi CORS origin (previously under ``http``)
      - ``auth.irma.cors.origin``
      - Only relevant when ``didmethods`` contains ``nuts``.
    * - Deprecated ``network.*`` TLS properties
      - (removed)
      - Configuring any deprecated network TLS property causes the node to refuse to start. Remove them.
    * - ``http.default.*`` and per-endpoint binding overrides
      - ``http.public.address`` / ``http.internal.address``
      - Endpoints are no longer individually bindable; see `HTTP interface split`_. The v5 ``http.default.tls`` and ``http.default.cors.origin`` keys no longer exist — TLS is handled by the proxy, and IRMA/Yivi CORS is set under ``auth.irma``.

API authentication
------------------

- Legacy bearer tokens (``token``) are removed. Only ``token_v2`` (JWT) is supported.
- API authentication applies only to ``/internal`` endpoints; public endpoints are unauthenticated by design.
- Configure ``http.internal.auth.type = token_v2`` and an ``authorized_keys`` file. Full reference: :ref:`nuts-node-api-authentication`.

Removed features
----------------

- UZI authentication means.
- ``purposeOfUseClaim`` in ``NutsAuthorizationCredential`` (removed).
- VDR v1 ``createDID``: the ``controller`` and ``selfControl`` fields are rejected. All ``did:nuts`` documents are self-controlled.

Deprecated APIs
---------------

The following v1 APIs still work in v6 but are scheduled for removal. Plan migration:

- Auth v1 → Auth v2.
- DIDMan v1 → no replacement; integrate via VDR v2 and the credential APIs.
- Network v1 → no replacement; ``did:nuts`` and the gRPC network are scoped to legacy use cases.
- VDR v1 → VDR v2.
- External key store API (secret store).

Startup migrations
==================

The node runs the migrations below on every startup, in order. Which ones run depends on ``didmethods``.

.. note::

    Migrations re-run on every restart. Updates made via the VDR v1 API land in SQL on the next restart.
    They are not propagated across other DIDs in the same subject — see `Stop using VDR v1 if the subject has more than one DID`_ for the upgrade decision this implies.

Convert did:nuts to self-control
--------------------------------

Runs when ``didmethods`` contains ``nuts``.

In v5, DID documents could be self-controlled or controlled by another DID (vendor / care organisation pattern).
v6 manages all DIDs through subjects, with every DID self-controlled.
The migration rewrites controller relationships so each owned ``did:nuts`` document is self-controlled.

Import did:nuts documents into SQL
----------------------------------

Runs when ``didmethods`` contains ``nuts``.

All owned ``did:nuts`` documents are imported into SQL storage under a subject with the same ID as the DID.
The migration imports the full history of document updates up to (and including) any deactivation.

For DIDs with an unresolved conflict, the migrated history will not match the resolver's merged view.
Resolve conflicts on v5 first — see `Resolve DID document conflicts`_.

Add did:web to subjects
-----------------------

Runs when ``didmethods`` contains both ``web`` and ``nuts`` (the default).

For each owned subject that does not already have a ``did:web`` document, a new ``did:web`` is created and added to the subject.
A new verification method is added to every relationship except ``KeyAgreement`` — ``did:web`` cannot yet be used for encryption.

Validating a migrated node
==========================

After v6 starts, verify the migration before routing production traffic:

- ``GET /status/diagnostics`` reports zero conflicted documents and the expected subject count.
- ``GET /internal/vdr/v2/subject`` lists a subject for every previously owned ``did:nuts`` DID.
- For each subject, ``GET /internal/vdr/v2/subject/{id}`` returns the expected DIDs (``did:nuts`` and, if enabled, ``did:web``).
- Resolve at least one of the new ``did:web`` documents over the public interface to confirm DNS, the reverse proxy, and ``url`` are wired up correctly.
- ``GET /status`` returns ``OK`` and ``GET /health`` reports all checks healthy on ``:8081``.
- Tail the logs on startup — failed migrations are logged at ``error`` and the node will not service requests until they complete.
