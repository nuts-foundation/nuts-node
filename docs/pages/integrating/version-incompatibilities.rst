.. _version-incompatibilities:

Version Incompatibilities
#########################

V5/V6, DID methods and API versions
***********************************

V6 introduced the support for multiple DID methods. To enable this, a new version of the VDR API has been added.
There's also a config parameter that allows you to limit the DID methods in use.
Not all combinations of API usage and DID methods are supported.
There are basically two options.

1. Keep using the VDR V1 API (for now) and set ``didmethods`` to ``["nuts"]``.
2. Use the VDR V2 API and set ``didmethods`` to include other methods or leave blank for default setting.

Do not use the VDR V1 and VDR V2 API at the same time. This will lead to unexpected behavior.
Once you use the VDR V2 API, you cannot go back to the VDR V1 API. The VDR V1 API has also been marked as deprecated.

Publishing Services for use-cases
*********************************

V5 use-cases define service endpoints or a collection of endpoints that should be registered in the Services on DID Documents.
The concrete endpoints are usually on the DID Document of the vendor, and then referenced by all DID Documents managed by that vendor.
And ``did:nuts`` for example, requires the registration of a ``NutsComm`` endpoint to authenticate the connection.
Use-cases built on V5 should keep using the DIDMan API to manage and resolve Services on DID Documents.
Any Service change made using the DIDMan API will only update ``did:nuts`` DID Documents.

For use-cases built on V6, any endpoint needed for the use-case should be listed in the registration on the Discovery Service for that use-case, see :ref:`discovery` Registration.
This means that ``did:web`` DID Documents (or non-did:nuts if we look further ahead) will contain very few Services, if any.
If there is a need to add a Service for V6 use-cases, they should be added using the VDR v2 API, which will then add the Service to _all_ DIDs that are part of the Subject.
Note that resolving Services using the VDR v2 API will return the Service from the document as is.
So, it resolves Services without following any references in the Service to a concrete endpoint as is done by DIDMan.