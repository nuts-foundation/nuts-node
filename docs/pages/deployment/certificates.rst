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

did:x509
********

In ``did:x509`` a certificate is converted to a DID Document (that includes its entire certificate chain) so it can be used in the Verifiable Credentials ecosystem.
This DID Method provides a temporary bridge between the 'old' world of CAs/Certificates and the 'new' Verifiable Credential world.
With other DID Methods, certificates are only used to create an secure channel for communication and optionally for client authentication.
In ``did:x509`` the certificates are also used in the cryptographic proofs to obtain access-tokens.
This means the certificate chain now provides the root of trust and has stricter requirements than connection certificates.

Trust in specific certificate CAs is configured per use-case in a :ref:`Discovery <discovery>` and :ref:`Policy <policy>` definition file.
CRLs from trusted chains (per the above definition files) are consulted when evaluating ``did:x509`` Verifiable Credentials.
For certificate chains used in ``did:x509`` the Nuts-node always uses a hard-fail strategy, i.e., the ``pki.softfail`` config value is ignored during certificate validation for ``did:x509``.
This means that the Nuts-node will not be able to verify a ``did:x509`` DID or Verifiable Credential signed by this DID Method if the CRL cannot be downloaded and the CRL in the cache is older than ``pki.maxupdatefailhours``.
