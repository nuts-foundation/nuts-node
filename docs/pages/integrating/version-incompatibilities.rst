.. _version-incompatibilities:

Version Incompatibilities
#########################

V5/V6, DID methods and API versions
***********************************

V6 introduced the support for multiple DID methods. To enable this, a new version of the VDR API has been added.
There's also a config parameter that allows you to limit the DID methods in use.
Not all combinations of API usage and DID methods are supported.
There are basically two options.

1. Keep using the VDR V1 API (for now) and set ``vdr.did_methods`` to ``["nuts"]``.
2. Use the VDR V2 API and set ``vdr.did_methods`` to include other methods or leave blank for default setting.

Do not use the VDR V1 and VDR V2 API at the same time. This will lead to unexpected behavior.
Once you use the VDR V2 API, you cannot go back to the VDR V1 API. The VDR V1 API has also been marked as deprecated.

Nodes running v6 with ``nuts`` configured as one of the ``vdr.did_methods`` will migrate all owned ``did:nuts`` DID documents to the new SQL storage.
This migration includes all historic document updates as published upto a potential deactivation of the document.
For DIDs with a document conflict this is different than the resolved version of the document, which contains a merge of all conflicting document updates.
To prevent the state of the resolver and the SQL storage to be in conflict, all DID document conflicts must be resolved before upgrading to v6.
See ``/status/diagnostics`` if you own any DIDs with a document conflict. If so, use ``/internal/vdr/v1/did/conflicted`` to find the DIDs with a conflict.

The document migration will run on every restart of the node, meaning that any updates made using the VDR V1 API will be migrated on the next restart.
When switching from the VDR V1 API to the V2 API, the node must be restarted first to migrate any recent changes.
