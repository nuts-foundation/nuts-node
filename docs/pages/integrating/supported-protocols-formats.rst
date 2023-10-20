.. _supported_protocols_and_formats:

Supported Protocols and Formats
===============================

This page documents which cryptographic algorithms, key types and SSI formats and protocols are supported.

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

Credentials
***********

`W3C Verifiable Credentials v1 <https://www.w3.org/TR/vc-data-model/>`_ and Presentations are supported (issuing and verifying) in JSON-LD and JWT format.

The following protocols are being implemented (work in progress):
- OpenID4VP verifier and SIOPv2 relying party for requesting a presentation from a wallet.
- OpenID4VCI issuer for issuing a credential to a wallet.
- OpenID4VCI wallet for receiving a credential from an issuer.