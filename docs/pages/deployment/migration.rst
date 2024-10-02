.. _nuts-node-migration:

Migrating from v5 to v6
************************

Nuts node v6 runs several migrations on startup for DID documents that are managed by the node, namely:

1. Remove controllers and add self-control to ``did:nuts`` documents,
2. Import ``did:nuts`` documents into the new SQL database under a ``subject`` with the same name, and
3. Add a ``did:web`` document with the same services to the same ``subject``.

**Migration: convert did:nuts to self-control**
Requires ``didmethods`` to contain ``nuts``.

Previously, DID documents could either by under self-control or under control of another DID as was recommended for vendor and care organisation, respectively.
In the new situation a user manages ``subject``s, and the node manages all DIDs under the ``subject``.
To reduce complexity and allow future adoption of other did methods, all documents will be under self-control from v6.

**Migration: convert did:nuts to subject**
Requires ``didmethods`` to contain ``nuts``.

All owned ``did:nuts`` DID documents will be migrated to the new SQL storage.
This migration includes all historic document updates as published upto a potential deactivation of the document.
For DIDs with a document conflict this is different than the resolved version of the document, which contains a merge of all conflicting document updates.
To prevent the state of the resolver and the SQL storage to be in conflict, all DID document conflicts must be resolved before upgrading to v6.
See ``/status/diagnostics`` if you own any DIDs with a document conflict. If so, use ``/internal/vdr/v1/did/conflicted`` to find the DIDs with a conflict.

.. note::

    The document migration will run on every restart of the node, meaning that any updates made using the VDR V1 API will be migrated on the next restart.
    However, any changes made via the V1 API wil NOT propagate to other DID documents under the same ``subject``, so you MUST set ``didmethods = ["nuts"]`` to use the V1 API.

**Migration: add did:web to subjects**
Requires ``didmethods`` to contain ``web`` and ``nuts`` (default).

This migration adds a new ``did:web`` DID Document to owned subjects that do not already have one.
All services from the ``did:nuts`` DID Document are copied to the new document.
A new verification method is created for the document and added to all verification relationships except KeyAgreement.
This means did:web cannot be used for encryption (yet).
