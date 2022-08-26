.. _connecting-ehr:

Getting Started on EHR integration
##################################

This getting started manual assumes the vendor and its clients (care organizations) are set up on the Nuts Network through :ref:`connecting-crm`.
The next step is to integrate the vendor's electronic health record (EHR) with the Nuts node to execute Bolts.

All APIs used in the following chapters are documented at the :ref:`API <nuts-node-api>` page.
There you will also find the OpenAPI specifications for generating client code.

Resolving Bolt endpoints
************************

Bolts define which technical endpoints should be defined for exchanging information.
These endpoints are grouped as services which are generally named after the Bolt they support.
The Nuts registry (as described by :ref:`connecting-crm`) can be queried to find care organizations that support a particular Bolt,
and to resolve the technical endpoints associated with it.

Searching organizations
=======================

To find care organizations (registered in the Nuts registry) that support a specific Bolt, the search organization API can be used.
It requires the ``query`` parameter to match organization names, and optionally a ``didServiceType`` (from its DID document).
If the DID service type is supplied, the API only returns the organizations who's DID Document contains a service of that type.

For example, the following API call searches the Nuts registry for organizations which name matches "Ziekenhuis" and have a service of type "secure-direct-messaging" on their DID Document:

.. code-block:: text

    GET <internal-node-address>/internal/didman/v1/search/organizations?query=Ziekenhuis&didServiceType=secure-direct-messaging

.. note::

    The example DID service type "secure-direct-messaging" could be defined by a (fictional) "Secure Direct Messaging" Bolt to be published by organizations that allow their employees to securely chat with other organizations through Nuts.

The API call returns a list of search results where each entry contains the organization and its last DID Document:

.. code-block:: json

    [
      {
        "didDocument": {
          "@context": "https://www.w3.org/ns/did/v1",
          "assertionMethod": [
            "did:nuts:JCx4c3ufdKNgaZJ4h54AghY8ZgCznptNpjHUtzvVgcvW#Cv0c4hlz4My7pKa6Wh6UN7gnTAXi5WUpNChqsUuIL1A"
          ],
          "controller": "did:nuts:5bSHwHtpSZfSCdCqaHvzDceEkjgNuKvTWVvQPB5DdeD9",
          "id": "did:nuts:JCx4c3ufdKNgaZJ4h54AghY8ZgCznptNpjHUtzvVgcvW",
          "verificationMethod": [
            /* etc */
          ],
          "service": {
            "type": "secure-direct-messaging",
            /* etc */
          }
        },
        "organization": {
          "city": "Doornenburg",
          "name": "Fort Pannerden"
        }
      }
    ]

For an organization to be returned as search results the following requirements must be met:

- It must have an active DID Document.
- The issuer of this DID document's verifiable credential (``NutsOrganizationCredential``) must be trusted by the local node.
- The verifiable credential must not be expired or revoked.

The ``query`` parameter is used to phonetically match the organization name: it supports partial matches and matches that sound like the given query.

Resolving endpoints
===================

When an organization has been selected, the next step is to resolve the technical endpoints.
This is done by taking the compound service as specified by the Bolt and resolving its endpoint references to an actual URL endpoints.
You can use the DIDMan ``getCompoundServiceEndpoint`` API operation for this.

Receiving Authorization Credentials
***********************************

Some Bolts require authorization credentials to authenticate data exchanges. These credentials are distributed privately over an authenticated connection.
To receive privately distributed credentials issued to your care organizations,
the DID documents of the care organizations need to contain a ``NutsComm`` service that references the vendor's.
See :ref:`setting up your node for a network <configure-node>` for how to achieve this.