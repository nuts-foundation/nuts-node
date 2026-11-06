.. _did:

Decentralized identifiers
#########################

Nuts uses `W3C Decentralized Identifiers <https://www.w3.org/TR/did-core/>`_ (DIDs) to identify parties.
A DID is backed by a *DID Document*: it lists the public keys of the party and optionally its services.
What DIDs are and which DID method a use case uses is described on the wiki: `Decentralized Identifiers <https://wiki.nuts.nl/link/195>`_.
The DID methods the Nuts node supports are listed in :ref:`supported_protocols_and_formats`.

Subjects
********

The Nuts node groups the DIDs of one party under a *subject*.
Creating a subject (``POST /internal/vdr/v2/subject``) creates a DID Document for each DID method in ``didmethods`` (default: ``web`` and ``nuts``).
Changes through the VDR V2 API, such as adding a key or a service, are made to all DID Documents of the subject.

DID Documents created by the Nuts node
**************************************

.. list-table::
   :header-rows: 1

   * -
     - ``did:web``
     - ``did:nuts``
   * - DID
     - ``did:web:<domain>:iam:<uuid>``, the domain is taken from ``url`` in the node configuration
     - ``did:nuts:<id>``, where the id is derived from the first key: the base58-encoded SHA-256 JWK thumbprint of that key
   * - Where the DID Document is published
     - Served by the node at ``https://<domain>/iam/<uuid>/did.json``
     - Sent to all nodes through the Nuts network when it is created
   * - Signing key
     - A new EC key, added to ``authentication``, ``assertionMethod``, ``capabilityInvocation`` and ``capabilityDelegation``
     - A new EC key, added to ``authentication``, ``assertionMethod``, ``capabilityInvocation`` and ``capabilityDelegation``
   * - Encryption key (``keyAgreement``)
     - Never added
     - The same key is added to ``keyAgreement``, unless the request sets ``keys.encryptionKey`` to ``false``

Azure Key Vault can't do encryption: with that key store, set ``keys.encryptionKey`` to ``false``, otherwise creating the subject fails.
New keys are added with ``POST /internal/vdr/v2/subject/{id}/verificationmethod``, see :ref:`key-rotation`.

Services
********

Use cases built on Nuts spec v2 list their endpoints in the registration on the Discovery Service, see :ref:`discovery`.
Use cases built on Nuts spec v1 list them as services in the ``did:nuts`` DID Document, see :ref:`version-incompatibilities`.
