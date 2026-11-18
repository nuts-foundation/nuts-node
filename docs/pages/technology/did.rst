.. _did:

Decentralized identifiers
#########################

Nuts uses `W3C Decentralized Identifiers <https://www.w3.org/TR/did-core/>`_ (DIDs) to identify parties.
A DID is backed by a *DID Document*: it lists the public keys of the party, who can change the document (its controllers) and its services.
What DIDs are and which DID method a use case uses is described on the wiki: `Decentralized Identifiers <https://wiki.nuts.nl/link/195>`_.
This version of the Nuts node supports the ``did:nuts`` method, see the `did:nuts specification (RFC006) <https://nuts-foundation.gitbook.io/drafts/rfc/rfc006-distributed-registry>`_.

DID Documents created by the Nuts node
**************************************

A DID Document is created with ``POST /internal/vdr/v1/did``:

- The DID is ``did:nuts:<id>``, where the id is derived from a new key: the base58-encoded SHA-256 JWK thumbprint of that key.
- The DID Document is sent to all nodes through the Nuts network.
- Changes are only accepted when the network transaction is signed with a ``capabilityInvocation`` key of a controller.

The request sets which DID controls the document and how the key is used:

.. list-table::
   :header-rows: 1

   * - Request field
     - Default
     - Effect
   * - ``selfControl``
     - ``true``
     - ``true``: the DID controls its own document with the new key. ``false``: the key the DID is derived from isn't added to the document, a second new key is added instead. Only the ``controllers`` can change the document.
   * - ``controllers``
     - none
     - Other DIDs that can change the document, e.g. the vendor DID for a care organization's DID.
   * - ``assertionMethod``
     - ``true``
     - The key signs credentials and access token requests.
   * - ``capabilityInvocation``
     - ``true``
     - The key can change the DID Document. Must be ``true`` when ``selfControl`` is ``true``.
   * - ``keyAgreement``
     - ``true``
     - The key is used for encryption.
   * - ``authentication``, ``capabilityDelegation``
     - ``false``
     -

All keys are EC keys (``JsonWebKey2020``). New keys are added with ``POST /internal/vdr/v1/did/{did}/verificationmethod``, see :ref:`key-rotation`.

Services
********

Use cases built on Nuts spec v1 list their endpoints as services in the DID Document.
How to register them is described on the wiki: `Set up DIDs and services <https://wiki.nuts.nl/link/199>`_.
