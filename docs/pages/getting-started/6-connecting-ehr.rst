.. _connecting-crm:

Getting Started on EHR integration
##################################

This getting started manual assumes the vendor and its clients (care organizations) are set up on the Nuts Network through :ref:`connecting-crm`.
The next step is to integrate the vendor's electronic health record (EHR) with the Nuts node to execute Bolts.

All APIs used in the following chapters are documented at the :ref:`API <nuts-node-api>` page.
Open API Spec files are available for generating client code.

Resolving Bolt endpoints
************************

Bolts define which technical endpoints should be defined for exchanging health information.
These endpoints are grouped as services which are generally named after the Bolt they support.
The Nuts registry (as described by :ref:`connecting-crm`) can be queried to find care organizations that support a particular Bolt,
and to resolve the technical endpoints associated with it.

Searching organizations
=======================

To find care organizations (registered in the Nuts registry) that support a specific Bolt, the search organization API can be used.
It takes a query parameter that's used to match organization names and optionally a DID service type.
If the DID service type is supplied the API only returns organizations which DID Document has a service with that type.

.. code-block:: text

    did:nuts:2mF6KT6eiSx5y2fwTP4Y42yMUh91zGVkbu4KMARvCJz9

For example, the following API call searches the Nuts registry for organizations which name matches "Ziekenhuis" and have a service of type "eOverdracht-receiver" on their DID Document:

.. code-block:: text

    GET <internal-node-address>/internal/didman/v1/search/organizations?query=Ziekenhuis&didServiceType=eOverdracht-receiver

.. note::

    The example DID service type "eOverdracht-receiver" is defined by the eOverdracht Bolt to be published by organizations that can accept patient transfers through Nuts.

The API call returns a list of search results where each entry contains the organization and its last DID Document.
For an organization to be returned as search results the following requirements must be met:

- It must have an active DID Document.
- Its verifiable credential (``NutsOrganizationCredential``) must be trusted by the local node.
- Its verifiable credential must not be expired or revoked.

The ``query`` parameter is used to phonetically match the organization name: it supports partial matches and matches that sound like the given query.

Resolving endpoints
===================

When an organization which supports the particular Bolt has been selected, the next step is to resolve the technical endpoints.
This is done by taking the compound service as specified by the Bolt and resolving each of its endpoint references to an actual URL endpoint.
These URL endpoints are then used to execute the Bolt.

.. note::

    There is an unresolved task to make resolving URL endpoints for a compound easier: https://github.com/nuts-foundation/nuts-node/issues/340