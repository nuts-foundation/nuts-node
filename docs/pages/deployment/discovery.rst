.. _discovery:

Discovery
#########

Discovery allows parties to publish information about themselves as a Verifiable Presentation,
so that other parties can discover them for further (data) exchange.

A Discovery Service is hosted on a server (also a Nuts node), by an organization that is agreed upon by the parties to be the server for that particular use case.
The parties implementing that use case then configure their Nuts nodes with the service definition that defines the server.

The service definition is a JSON document agreed upon (and loaded) by all parties that specifies:

- which Verifiable Credentials are registered on the service,
- where the Discovery Service is hosted, and
- how often the Verifiable Presentations must be updated.

Service definitions are loaded from the ``discovery.definitions.directory`` directory by both client and server.
It does not load subdirectories. If the directory contains JSON files that are not (valid) service definitions, the node will fail to start.

Clients
*******

Clients will periodically refresh the loaded Discovery Services. Applications can then search for entries in the Discovery Service, e.g.:

.. code-block:: http

    GET /internal/discovery/v1/discovery/addressbook2024:dev/?credentialSubject.name=John%20Doe

Registration
============

To register a DID on a Discovery Service, the DID must be activated for the service.
The Nuts node will then register a Verifiable Presentation of the DID on the service, and periodically refresh it.
E.g., for service ``addressbook2024:dev`` and DID ``did:web:example.com``:

.. code-block:: http

    POST /internal/discovery/v1/addressbook2024:dev/did:web:example.com

The DID's wallet must contain the Verifiable Credential(s) that are required by the service definition,
otherwise registration will fail. If the wallet does not contain the credentials,
the Nuts node will retry registration periodically.

Servers
*******
To act as server for a specific discovery service, its service ID needs to be specified in ``discovery.server.defition_ids``, e.g.:

.. code-block:: yaml

    discovery:
      server:
        definition_ids:
          - "addressbook2024:dev"

The IDs in this list must correspond to the ``id`` fields of the loaded service definition, otherwise the node will fail to start.

Clients will access the discovery service through ``/discovery`` on the external HTTP interface (``8080`` by default),
so make sure it's available externally.

The endpoint for a Discovery Service as it must be specified in the definition is the service ID appended to this base URL,
e.g.: ``/discovery/addressbook2024:dev``.
