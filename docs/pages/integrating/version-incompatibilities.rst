.. _version-incompatibilities:

Version Incompatibilities
#########################

V5/V6, DID methods and API versions
***********************************

V6 introduced the support for multiple DID methods. To enable this, a new version of the VDR API has been added.
There's also a config parameter that allows you to limit the DID methods in use.
Not all combinations of API usage and DID methods are supported.
There are basically two options.

1. Keep using the VDR V1 API (for now) and set ``vdr.did_methods`` to ``["nuts"]``.
2. Use the VDR V2 API and set ``vdr.did_methods`` to include other methods or leave blank for default setting.

Do not use the VDR V1 and VDR V2 API at the same time. This will lead to unexpected behavior.
Once you use the VDR V2 API, you cannot go back to the VDR V1 API. The VDR V1 API has also been marked as deprecated.
