.. _usecase-certificates:

Certificates (did:x509)
#########################

Trust in specific certificate CAs for ``did:x509`` is configured per use-case in a :ref:`Discovery <discovery>` and :ref:`Access policies <policy>` definition file.
CRLs from the trusted chains (per those definition files) are consulted when evaluating ``did:x509`` Verifiable Credentials.
See :ref:`Certificate revocation (CRL) handling <certificate-revocation-handling>` for how a failure to download a CRL is handled — for ``did:x509`` this always hard-fails.

For background on why ``did:x509`` uses certificate chains as its root of trust, see :ref:`did:x509 <did-x509-background>`.
