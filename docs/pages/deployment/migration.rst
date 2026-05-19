.. _nuts-node-migration:
.. _nuts-node-migrations:

Migrating from v5 to v6
***********************

Operator runbook for upgrading a v5 deployment to v6 while keeping the existing ``did:nuts`` setup. Work through the steps in order. If you also want to adopt ``did:web`` as part of the upgrade, finish the main steps first, then see :ref:`also-enabling-did-web`.

.. contents::
    :local:
    :depth: 1

1. Provision an SQL database
============================

v6 requires SQL storage. Supported engines: PostgreSQL, MySQL, Microsoft SQL Server, Azure SQL, SQLite.
SQLite is acceptable for small deployments, and for ``did:nuts``-only deployments that won't adopt ``did:web`` in the near future — in that case the SQL state is rebuilt at startup from BBolt and the key backend.
Move to PostgreSQL, MySQL, MSSQL, or Azure SQL before adopting ``did:web``.

Configure the connection string in ``storage.sql.connection``. See :ref:`storage-configuration` for the full reference.

.. code-block:: yaml

    # SQLite — fine for a did:nuts-only upgrade
    storage:
      sql:
        connection: sqlite:file:/opt/nuts/data/sqlite.db?_pragma=foreign_keys(1)&journal_mode(WAL)

2. Update the host and container references
===========================================

The v6 container runs as UID ``18081`` (was ``root``). Before the first v6 start, on the host:

.. code-block:: shell

   chown -R 18081:18081 /opt/nuts/data

Docker image tags no longer carry a ``v`` prefix — pull ``nutsfoundation/nuts-node:6.0.0``, not ``v6.0.0``.

3. HTTP interfaces
==================

v5 supported flexible HTTP binding via ``http.<name>.*`` (with ``http.default.*`` as the default interface; operators could define additional named interfaces like ``http.admin.*`` bound to separate addresses). v6 replaces this with two fixed interfaces — update your reverse proxy / ingress to route accordingly:

- ``:8080`` (``http.public.address``) — public endpoints (``/iam``, ``/oauth2``, ``/n2n``, ``/.well-known``, …).
- ``127.0.0.1:8081`` (``http.internal.address``) — ``/internal``, ``/status``, ``/metrics``, ``/health``. Loopback only by default; if you need to access it from another host, set ``http.internal.address`` to ``0.0.0.0:8081`` and make sure it is not accessible to unauthorized callers (firewall, network segmentation, auth).

See :ref:`nuts-node-recommended-deployment` for a reference topology.

4. Adjust the config file
=========================

Set ``didmethods = ["nuts"]`` (unless you are also adopting ``did:web`` — see :ref:`also-enabling-did-web`). The v6 default is ``["web", "nuts"]``; setting it explicitly to ``["nuts"]`` keeps the deployment behaviour aligned with v5.

Remove or rename the following:

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - v5 key
     - Action
   * - ``auth.publicURL``
     - Replace with the new top-level ``url`` (introduced in v6).
   * - All ``http.<name>.*`` interface bindings (``http.default.address``, ``http.default.tls``, ``http.default.cors.origin``, and any custom-named interfaces)
     - Remove. v6 uses fixed ``http.public.address`` and ``http.internal.address``.
   * - IRMA/Yivi CORS origin
     - Move to ``auth.irma.cors.origin``.
   * - ``network.certfile``, ``network.certkeyfile``, ``network.truststorefile``
     - Rename to ``tls.certfile``, ``tls.certkeyfile``, ``tls.truststorefile``. v6 refuses to start otherwise.
   * - ``http.internal.auth.type = token``
     - No longer accepted. Either configure ``token_v2`` (see :ref:`nuts-node-api-authentication`) or rely on another authentication mechanism on the internal interface — reverse-proxy auth, mTLS, or network-level controls.

5. Start v6
===========

Back up the v5 data directory first — see `Rolling back`_.

Bring up the v6 node. On first start it runs the ``did:nuts`` migrations (self-control rewrite and history import into SQL). The migrations are idempotent and re-run on every restart, so an interrupted upgrade is safe to retry.

6. Check the startup logs
=========================

Schema migrations abort startup on failure — if the node booted, those are fine. The DID-document migrations don't: per-DID failures (corrupted history, key resolution errors) are logged at ``error`` and the node keeps running with that DID missing from SQL. Grep the startup logs for ``level=error`` lines from the migration step.

Rolling back
============

v6 rewrites the v5 on-disk state on first start. There is no in-place downgrade. To roll back, restore the v5 data directory from the backup you took before Step 5, then start v5. The SQL database is new in v6 and not used by v5. If you plan to retry the upgrade, wipe the SQL database first to avoid stale state.

Other notes
===========

TLS termination
---------------

v6 no longer terminates server-side TLS for HTTP itself. If you already run v5 behind a reverse proxy or ingress (the typical setup), no change is needed. If you relied on the node's built-in TLS, move termination to a reverse proxy or ingress before upgrading.

Creating DIDs with ``selfControl=false``
----------------------------------------

``POST /internal/vdr/v1/did`` ignores the request body in v6. The v5 vendor-controls-care-organisation pattern is gone — new DIDs are always self-controlled, and existing ones are flattened to self-control by the startup migration.

Mixing VDR v1 and v2 APIs
-------------------------

The v1 and v2 APIs read from different stores. Do not mix usage, or you risk data drift and stale reads. VDR v1 / DIDMan v1 are deprecated and slated for removal in a future major release.

.. _also-enabling-did-web:

Also enabling ``did:web``
-------------------------

If you also want to support ``did:web`` use cases, leave ``didmethods`` at its default (both methods enabled) — drop the ``didmethods = ["nuts"]`` line from Step 4. The startup migration adds a ``did:web`` document to every existing subject; this is one-way and cannot be reversed without manually rebuilding subjects.

Additional preconditions:

- **Resolve all DID document conflicts on v5 first.** A conflicted ``did:nuts`` document imports into SQL as the replayed published history, not the merged state the v1 resolver returns. The new ``did:web`` is derived from the SQL view, so for any conflicted DID it will diverge from what v1 callers see. On v5, check ``GET /status/diagnostics``; if any are owned, list them via ``GET /internal/vdr/v1/did/conflicted`` and resolve each one.
- **Move all DID and service management to VDR v2 before the first multi-method write.** VDR v1 / DIDMan v1 writes only touch the ``did:nuts`` document, not the ``did:web`` in the same subject. Mixed use silently desynchronises the two, and the startup migrations do not repair this on later restarts.
- ``did:web`` resolution requires the public interface to be reachable at the configured ``url`` over HTTPS (handled by the reverse proxy from Step 3).

After the first v6 start with ``did:web`` enabled, verify each subject contains both DIDs:

- ``GET /internal/vdr/v2/subject/{id}`` lists both the ``did:nuts`` and the ``did:web``.
