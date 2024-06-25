.. _did:

Decentralized identifiers
#########################

Nuts uses `W3C Decentralized Identifiers <https://www.w3.org/TR/did-core/>`_ as a base for tracking identities.
From the W3C website:

    Decentralized identifiers (DIDs) are a new type of identifier that enables verifiable, decentralized digital identity. A DID identifies any subject (e.g., a person, organization, thing, data model, abstract entity, etc.) that the controller of the DID decides that it identifies. In contrast to typical, federated identifiers, DIDs have been designed so that they may be decoupled from centralized registries, identity providers, and certificate authorities. Specifically, while other parties might be used to help enable the discovery of information related to a DID, the design enables the controller of a DID to prove control over it without requiring permission from any other party. DIDs are URIs that associate a DID subject with a DID document allowing trustable interactions associated with that subject.

Within Nuts, DIDs identify different parties. All DID methods require their own specification.
The Nuts specification for the `nuts` DID method can be found on https://nuts-specification.readthedocs.io.
Nuts DIDs are designed so they represent public/private key pairs. Any party can generate and claim a key pair.
Only when information is added to the key pair, the key pair becomes important.

DIDs can gather claims through Verifiable Credentials. This allows a DID to actually represent something known in real life.
For example: adding an organization name credential connects the key pair to the name of the organization. It connects the digital world to the real world.

Nuts DID Documents
******************

DIDs are backed by a *DID Document*. It defines the public keys, who can alter the document and any services related to the DID.
Nuts DID documents are automatically propagated through the network when they are created.
When DID documents are created, the DID **always** represents the public key fingerprint of the associated key.
A DID document is always created with a new key, the holder of the key can delegate the control to another DID.

Verification Method
===================

All public keys within a Nuts DID Document are listed under **verificationMethod**.

Assertion Method
================

Keys referenced from the **assertionMethod** section are used to sign JWTs in the OAuth flow and for issuing *Verifiable Credentials*.

Authentication Method
=====================

Keys referenced from the **authentication** section are used to change the DID document and sign network transactions.

Services
========

The **services** section is used to list service endpoints. There are some endpoints that are shared amongst all services, like the **oauth** service.
But most service endpoints will be coming from specific `Bolts <https://nuts-foundation.gitbook.io/bolts/>`_.
