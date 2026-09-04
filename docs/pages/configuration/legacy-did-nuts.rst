.. _legacy-did-nuts-configuration:

Legacy did:nuts configuration
##############################

This page covers configuration that's only relevant for use cases that still use ``did:nuts`` DIDs and/or the Nuts gRPC network.
If your use case does not use these features, you can ignore this page.

Options
*******

The following table contains additional (deprecated) options that are relevant for use cases that use ``did:nuts`` DIDs and/or the gRPC network:

.. include:: server_options_didnuts.rst

Client authentication
**********************

The ``/n2n`` endpoints and the ``gRPC Nuts network`` use TLS certificates for client authentication.
The Nuts-node validates the client certificates used by its peers on the ``gRPC network`` when a new connection is established, and periodically after that as long as the connection exists.
To do this, all trusted certificate chains must be configured in ``tls.truststorefile``.
See :ref:`Certificate revocation handling <certificate-revocation-handling>` for how CRL checks and soft-fail behavior work for these certificates.
The ``gRPC Nuts network`` and ``/n2n`` endpoints are deprecated and will be removed in the future.

Publishing services for use cases
**********************************

V5 use-cases define service endpoints or a collection of endpoints that should be registered in the Services on DID Documents.
The concrete endpoints are usually on the DID Document of the vendor, and then referenced by all DID Documents managed by that vendor.
``did:nuts`` for example, requires the registration of a ``NutsComm`` endpoint to authenticate the connection.
Use-cases built on ``did:nuts`` should keep using the DIDMan API to manage and resolve Services on DID Documents.
Any Service change made using the DIDMan API will only update ``did:nuts`` DID Documents.

For use-cases built on v6 and later, any endpoint needed for the use-case should instead be listed in the registration on the :ref:`Discovery Service <discovery>` for that use-case.
This means that ``did:web`` DID Documents (or non-did:nuts if we look further ahead) will contain very few Services, if any.
If there is a need to add a Service for these use-cases, they should be added using the VDR v2 API, which will then add the Service to _all_ DIDs that are part of the Subject.
Note that resolving Services using the VDR v2 API will return the Service from the document as is.
So, it resolves Services without following any references in the Service to a concrete endpoint, as is done by DIDMan.
