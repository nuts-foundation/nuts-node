.. _connecting-crm:

Getting Started on customer integration
#######################################

This getting started manual assumes a vendor sells services to its customers.
The vendor manages the presence of those customers on the Nuts network through the Nuts registry.
It's very likely the vendor has software to manage customer environments. We'll call it a *CRM* where the *customers* part relates to organizations and not people.
This does not mean that a stand-alone installation isn't supported. In that case the vendor and organization are the same.

The Nuts registry enables service discovery for organizations. The registry identifies organizations through their :ref:`DID <did>`.
The DIDs are unique identifiers which are generated when the organization is registered in the Nuts registry.
After creation of the DID the CRM should store and map it to its customer record, so it can refer to it when updating the customer's DID Document and issue Verifiable Credentials.

All APIs used in the following chapters are documented at the :ref:`API <nuts-node-api>` page.
Open API Spec files are available for generating client code.

Vendor integration
******************

As a vendor, you're in power of:

- running a Nuts node
- handling organization key material
- updating the organization DID Document
- defining service endpoints
- issuing name credentials for organizations
- trusting other vendors

The last three points require a setup where a vendor DID is created. This DID will act as the controller of all organization DID Documents.
This will allow for reuse of service endpoints and issuance of Verifiable Credentials.
Since every DID issuing Verifiable Credentials must be trusted individually, it's easier for other vendors when the vendor uses a single DID for issuing credentials.

Create and store a vendor DID
=============================

Your CRM must store the DIDs created for your vendor and your customers. A DID is a string similar to:

.. code-block:: text

    did:nuts:2mF6KT6eiSx5y2fwTP4Y42yMUh91zGVkbu4KMARvCJz9

The DID we're about to create is your *vendor DID*. It will be used in the all of the next steps.
For the API calls that will need to be made to the Nuts node, we'll use ``<internal-node-address>`` as the address where the internal API's are exposed.
Consult the :ref:`configuration reference <nuts-node-config>` on how to configure the node address.

.. code-block:: text

    POST <internal-node-address>/internal/vdr/v1/did
    {
        "selfControl": true,
        "assertionMethod": true,
        "capabilityInvocation": true
    }

The request above instructs the node to create a new DID and DID Document. The DID Document will be published to all other nodes.
The node will generate a new keypair and store it in the crypto backend.
The options above will instruct the node to allow the DID Document to be changed by itself (``selfControl = true AND capabilityInvocation = true``) and that the DID can be used to issue credentials (``assertionMethod = true``).
If all is well, the node will respond with a DID Document similar to:

.. code-block:: json

    {
      "@context": [ "https://www.w3.org/ns/did/v1" ],
      "id": "did:nuts:2mF6KT6eiSx5y2fwTP4Y42yMUh91zGVkbu4KMARvCJz9",
      "verificationMethod": [
        {
          "id": "did:nuts:2mF6KT6eiSx5y2fwTP4Y42yMUh91zGVkbu4KMARvCJz9#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
          "controller": "did:nuts:2mF6KT6eiSx5y2fwTP4Y42yMUh91zGVkbu4KMARvCJz9",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "crv": "P-256",
            "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
            "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
            "kty": "EC"
          }
        }],
      "capabilityInvocation": [
        "did:nuts:2mF6KT6eiSx5y2fwTP4Y42yMUh91zGVkbu4KMARvCJz9#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw"
      ],
      "assertion": [
        "did:nuts:2mF6KT6eiSx5y2fwTP4Y42yMUh91zGVkbu4KMARvCJz9#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw"
      ],
      "service": []
    }

The ``id`` at the top level needs to be extracted and stored as your vendor DID.
In the example above this would be ``did:nuts:2mF6KT6eiSx5y2fwTP4Y42yMUh91zGVkbu4KMARvCJz9``.
The DID Document shouldn't be stored since the Nuts node will do this for you.

Setting vendor contact information
==================================

Things can go wrong: a node is misbehaving or a DID Document is conflicted.
If the node operator is not resolving the problem it's extremely convenient if others can contact the node operator and relay the problem.
For this use-case, Nuts supports the registration of node contact information. The contact information will be added to a DID Document as a service.
A convenience API is available to add the contact information to a DID Document. The vendor DID should be used for this.

.. code-block:: text

    PUT <internal-node-address>/internal/didman/v1/did/<did>/contactinfo
    {
        "name": "vendor X",
        "phone": "06-12345678",
        "email": "info@example.com",
        "website": "https://example.com"
    }

Where ``<did>`` must be replaced with the vendor DID.

Adding endpoints
================

As a vendor you'll probably be hosting different services at various stages. A Nuts node API is available to easily add/remove the endpoints for these services.
Registering services is a required step since the services that will be registered for organizations will make use of these services.

.. code-block:: text

    POST <internal-node-address>/internal/didman/v1/did/<did>/endpoint
    {
        "type": "example-production-api",
        "endpoint": "https://api.example.com"
    }

Where ``<did>`` must be replaced with the vendor DID. The ``type`` may be freely chosen and is used as reference in the organization services.
The ``endpoint`` must be a valid endpoint (this differs per type of service).
For some services this could be a base-url. If this is the case, the bolt description will note this.

Organization integration
************************

Each organization (or customer) must be registered with its own DID and DID Document.
The vendor CRM should make it possible to store a DID for each organization.
Requests that are made in the context of the organization will use the private key of the organization.
To easily control the DID Document of an organization, the vendor will be the controller.

Create and store a customer DID
===============================

A DID can be created like the vendor DID:

.. code-block:: text

    POST <internal-node-address>/internal/vdr/v1/did
    {
        "selfControl": false,
        "controllers": [<did>],
        "assertionMethod": true,
        "capabilityInvocation": false
    }

Where ``<did>`` must be replaced with the vendor DID.
The body for creating an organization DID differs from the vendor DID in the fact that the vendor DID is in control of the newly generated DID Document.
The ``assertionMethod`` is still true since it'll allow for the generation of access-tokens in the context of the organization.
The result is similar to the output of the vendor DID creation.
In this case the ``id`` must also be extracted and stored within the vendor CRM for the right organization.

Issue a Nuts Organization Credential
====================================

After registering an organization, its presence on the network and in the Nuts registry is now only a DID.
In order for other organizations to find the correct DID and connected services, credentials should be issued and published over the network.
For this, the *NutsOrganizationCredential* can be issued by any vendor.
A *NutsOrganizationCredential* contains the ``name`` of the organization and the ``city`` where this name is registered as organization.
The combination of those should be unique (since duplicate names within a sector is disallowed).

A credential can be issued with the following call:

.. code-block:: text

    POST <internal-node-address>/internal/vcr/v1/vc
    {
        "type": "NutsOrganizationCredential",
        "issuer": "<issuer-did>",
        "credentialSubject": {
            "id": "<holder-did>",
            "organization": {
                "name": "<name>",
                "city": "<city>"
            }
        }
    }

Where ``<issuer-did>`` must be replaced with the vendor DID, ``<holder-did>`` must be replaced with the organization DID,``<name>`` and ``<city>`` must be replaced with the correct information.
The API will respond with the full Verifiable Credential. It's not required to do anything with that since issued credentials can be found again.
:ref:`This page <vc-concepts>` contains some more information on specific credentials.

Trusting other vendors as issuer
================================

A node operator must not blindly trust all the data is published over the network. Before credentials can be found, the issuer has to be trusted.
By default, no issuers are trusted. A list of untrusted issuers can be obtained from the node through:

.. code-block:: text

    GET <internal-node-address>/internal/vcr/v1/NutsOrganizationCredential/untrusted

This will return a list of all DIDs that are currently not trusted. If a DID is to be trusted should be validated out-of-band, eg: by phone or video conference call.
The registered contact information for that DID could help in contacting the right party. Be aware that the provided contact information isn't verified.
So instead of asking: "is this your DID?", ask: "could you please tell me your DID?".
After a DID has been verified, it can be trusted by calling the following API:

.. code-block:: text

    POST <internal-node-address>/internal/vcr/v1/trust
    {
        "issuer": "<did>",
        "credentialType": "NutsOrganizationCredential"
    }

Where ``<did>`` must be replaced with the validated DID.
It's also possible to update the ``vcr/trusted_issuers.yaml`` file located in the data directory (configured via the ``datadir`` property).
After a vendor has been trusted, any of its registered organizations should be searchable by name.

.. note::

    Future development will see new cryptographic means. These means could enable the organization to self-register its name.
    The network should then migrate to a trust model where the issuer of those means is trusted instead of the different vendors.

Enabling a bolt
===============

Organizations can be found on the network and endpoints have been defined.
Now it's time to enable specific bolts so users can start using data from other organizations.
Every bolt requires its own configuration. This configuration is known as a Compound Service on the organization's DID document.
A Compound Service defines certain endpoint types and which endpoint to use for that type.

A Compound Service can be added with the following request:

.. code-block:: text

    POST <internal-node-address>/internal/didman/v1/did/<did>/compoundservice
    {
        "type": "<type>",
        "endpoint": {
            "<X>": "<endpoint_did>?type=<Y>",
            ...
        }
    }

The parameters must be replaced:

-  ``<did>`` must be replaced with the organization DID.
-  ``<type>`` must be replaced with the type defined by the bolt specification.
- ``<endpoint_did>`` must be replaced with the vendor DID that defines the endpoints.
- ``<X>`` must be replaced with the type required by the bolt specification.
  All types defined by the specification must be added, unless stated otherwise.
- ``<Y>`` must be replaced with the correct endpoint type from the vendor DID Document.
  ``<endpoint_did>?type=<Y>`` must be a valid query within the corresponding DID Document.


For example, the `eOverdracht sender <https://nuts-foundation.gitbook.io/bolts/eoverdracht/leveranciersspecificatie#4-1-2-organisatie-endpoint-discovery>`_ requires an ``eOverdracht-sender`` Compound Service with two endpoints: an ``oauth`` endpoint and a ``fhir`` endpoint.
The example can be added by the following request:

.. code-block:: text

    POST <internal-node-address>/internal/didman/v1/did/did:nuts:organization_identifier/compoundservice
    {
        "type": "eOverdracht-sender",
        "endpoint": {
            "oauth": "did:nuts:vendor_identifier?type=production-oauth",
            "fhir": "did:nuts:vendor_identifier?type=eOverdracht-sender-fhir"
        }
    }

.. note::

    As specified by `RFC006 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc006-distributed-registry#4-services>`_, the ``type`` MUST be unique within a DID Document.
