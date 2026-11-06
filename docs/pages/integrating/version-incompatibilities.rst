.. _version-incompatibilities:

Version Incompatibilities
#########################

V5/V6, DID methods and API versions
***********************************

V6 introduced the support for multiple DID methods. To enable this, a new version of the VDR API has been added.
There's also a config parameter that allows you to limit the DID methods in use.
Not all combinations of API usage and DID methods are supported.
There are basically two options.

1. Keep using the VDR V1 API (for now) and set ``didmethods`` to ``["nuts"]``.
2. Use the VDR V2 API and set ``didmethods`` to include other methods or leave blank for default setting.

Do not use the VDR V1 and VDR V2 API at the same time. This will lead to unexpected behavior.
Once you use the VDR V2 API, you cannot go back to the VDR V1 API. The VDR V1 API has also been marked as deprecated.

Publishing Services for use-cases
*********************************

Use-cases built on Nuts spec v1 publish their endpoints as Services in ``did:nuts`` DID Documents.
These are managed with the DIDMan API.
After upgrading the Nuts node to V6, you can manage these Services with the VDR V2 API instead.
The VDR V2 API adds a Service to all DIDs of the subject, and resolves Services as they are in the DID Document,
without following references to a concrete endpoint (as DIDMan does).

.. warning::
   Once you manage Services with the VDR V2 API, you MUST NOT use the DIDMan API or the VDR V1 API anymore.
   VDR V2 keeps the DID Documents of a subject (e.g. its ``did:web`` and ``did:nuts`` DIDs) in sync;
   changes made through DIDMan or VDR V1 only update the ``did:nuts`` DID Document, so the DID Documents get out of sync.

Use-cases built on Nuts spec v2 list their endpoints in the registration on the Discovery Service, see :ref:`discovery`.
How this works is described on the wiki: `Decentralized Identifiers <https://wiki.nuts.nl/link/195>`_.
