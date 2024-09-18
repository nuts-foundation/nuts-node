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
A DID document is always created with a new key. Signing keys are are added to the `authentication`, `assertionMethod`, `capabilityInvocation` and `capabilityDelegation` sections.
Encryption keys are added to the `keyAgreement` section.

Services
========

The **services** section is used to list service endpoints. Although still available, the preferred way is to register services via :ref:`discovery`.
