.. _certificate-revocation-handling:

Certificate revocation (CRL) handling
#######################################

The Nuts-node periodically downloads the Certificate Revocation List (CRL) of configured trusted certificate chains to confirm a certificate has not been revoked.
This applies to the ``tls.truststorefile`` used for :ref:`legacy did:nuts/gRPC client authentication <legacy-did-nuts-configuration>`, and to the certificate chains trusted per use case for :ref:`did:x509 <did-x509-background>`.

Soft-fail vs. hard-fail
************************

By default the node uses a soft-fail strategy: it does not reject a certificate if the CRL cannot be downloaded.
This prevents a CA with downtime on its CRL endpoint from bringing down the network.
Change this to hard-fail (reject the certificate if its revocation status cannot be established) using the ``pki.softfail`` config flag.

For ``did:x509`` the node always uses a hard-fail strategy: the ``pki.softfail`` config value is ignored during certificate validation for ``did:x509``.
This means the node will not be able to verify a ``did:x509`` DID or Verifiable Credential if the CRL cannot be downloaded and the cached CRL is older than ``pki.maxupdatefailhours``.

Operational guidance
**********************

If you use ``did:x509``, monitor CRL fetch failures and keep ``pki.maxupdatefailhours`` tuned to the actual refresh cadence of your CAs' CRLs — since failures always hard-fail for did:x509, a CRL endpoint outage that outlasts this window will start rejecting otherwise-valid credentials.
For legacy did:nuts/gRPC client authentication, the default soft-fail behavior is usually appropriate; switch to hard-fail only if your use case requires certificate validity to always be provable.
