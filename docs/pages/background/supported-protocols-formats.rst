.. _supported_protocols_and_formats:

Supported Protocols and Formats
===============================

This page documents which cryptographic algorithms, key types and SSI formats and protocols are supported.
Various protocols have a draft status and success on using them may vary.

Cryptographic Algorithms
************************
The following cryptographic signing algorithms are supported:

- ECDSA with the NIST P-256, P-384 and P-512 curves.
- EdDSA with Ed25519 curves.
- RSASSA-PSS RSA with keys of at least 2048 bits.

The following encryption algorithms are supported:

- RSA-OAEP-SHA256 (min. 2048 bits)
- ECDH-ES+A256KW
- AES-GCM-256

DID methods
***********

The following DID methods are supported:

- ``did:nuts`` (creating and resolving)
- ``did:web`` (creating and resolving)
- ``did:key`` (resolving)
- ``did:jwk`` (resolving)
- ``did:x509`` (resolving, except the "eku" policy type, additionally the "san" "otherName" policy)

Credentials
***********

`W3C Verifiable Credentials v1 <https://www.w3.org/TR/vc-data-model/>`_ and Presentations are supported (issuing and verifying) in JSON-LD and JWT format.

The following protocols are being implemented (work in progress):

- OpenID4VP verifier and SIOPv2 relying party for requesting a presentation from a wallet.
- OpenID4VCI issuer for issuing a credential to a wallet.
- OpenID4VCI wallet for receiving a credential from an issuer.


DIIP Compliance
***************

We strive to be complient with the `DIIP components <https://dutchblockchaincoalition.org/bouwstenen/diip-2>`_ as specified by the Dutch Blockchain Coalition.
The following components are supported:

.. role:: green

1. OpenID for Verifiable Credential Issuance :green:`✓` (wallet only)
2. OpenID for Verifiable Presentations :green:`✓`
3. SIOP V2 (Not relevant for organisation wallet agents)
4. DIF Presentation Exchange :green:`✓`
5. W3C Verifiable Credential JWT :green:`✓`
6. DID methods: ``did:web`` and ``did:jwk`` :green:`✓`
7. Signature types ``ES256`` :green:`✓`
8. Revocation method: StatusList 2021 :green:`✓`
