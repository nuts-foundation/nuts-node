.. _certificates:

Certificates
############

client authentication
*********************

Nuts-node versions before v6 only use TLS certificates for client authentication on the ``/n2n`` endpoints and in the ``gRPC Nuts network``.
The Nuts-node also validates the client certificates used by its peers on the ``gRPC network`` when a new connection is established, and periodically after that as long as the connection exists.
To do this, all trusted certificate chains must be configured in ``tls.truststorefile``.
The Certificate Revocation List (CRL) of the CAs in the truststore are periodically downloaded to confirm a peer's client certificate is not revoked.
To prevent a CA with downtime on its CRL endpoint from bringing down the network, the Nuts-node uses a soft-fail strategy that does not reject certificates if it cannot download the CRL.
This behavior can be changed to hard-fail (fail if certificate is invalid, expired, of revoked, or if any of the previous cannot be determined) using the ``pki.softfail`` config flag.
The ``gRPC Nuts network`` and ``/n2n`` endpoints are deprecated and will be removed in the future.

outbound HTTPS
**************

Certificates of public web servers the Nuts-node connects to (e.g. for ``did:web`` resolution, OAuth2, Discovery and status lists) are checked against the CRLs of their CAs and the denylist.
The Nuts-node must be able to reach the CRL endpoints of these CAs, which usually use plain HTTP.
The ``pki.softfail`` config flag decides what happens if a CRL or the denylist cannot be retrieved. Revoked and denied certificates are always rejected.
If CRLs or the denylist have not been downloaded yet, a connection waits at most 3 seconds for them. The downloads continue in the background, so later connections are checked against them.

did:x509
********

In ``did:x509`` a certificate is converted to a DID Document (that includes its entire certificate chain) so it can be used in the Verifiable Credentials ecosystem.
This DID Method provides a temporary bridge between the 'old' world of CAs/Certificates and the 'new' Verifiable Credential world.
With other DID Methods, certificates are only used to create an secure channel for communication and optionally for client authentication.
In ``did:x509`` the certificates are also used in the cryptographic proofs to obtain access-tokens.
This means the certificate chain now provides the root of trust and has stricter requirements than connection certificates.

Certificates and CRLs in the chain may be signed with RSA (PKCS #1 v1.5 or RSASSA-PSS, with SHA-256, SHA-384 or SHA-512), ECDSA or Ed25519.
This includes the PKIoverheid G4 profile used for UZI server certificates issued from 12 November 2026: RSA 4096 keys with RSASSA-PSS/SHA-512 signatures.

Trust in specific certificate CAs is configured per use-case in a :ref:`Discovery <discovery>` and :ref:`Policy <policy>` definition file.
CRLs from trusted chains (per the above definition files) are consulted when evaluating ``did:x509`` Verifiable Credentials.
For certificate chains used in ``did:x509`` the Nuts-node always uses a hard-fail strategy, i.e., the ``pki.softfail`` config value is ignored during certificate validation for ``did:x509``.
This means that the Nuts-node will not be able to verify a ``did:x509`` DID or Verifiable Credential signed by this DID Method if the CRL cannot be downloaded and the CRL in the cache is older than ``pki.maxupdatefailhours``.
