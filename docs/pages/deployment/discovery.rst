.. _discovery:

Discovery
#########

Discovery allows parties to publish information about themselves as a Verifiable Presentation,
so that other parties can discover them for further (data) exchange.

A Discovery Service is hosted on a server (also a Nuts node), by an organization that is agreed upon by the parties to be the server for that particular use case.
The parties implementing that use case then configure their Nuts nodes with the service definition that defines the server.

The service definition is a JSON document agreed upon (and loaded) by all parties that specifies:

- which Verifiable Credentials are required for the service,
- where the Discovery Service is hosted, and
- how often the Verifiable Presentations must be updated.

Service definitions are loaded from the ``discovery.definitions.directory`` directory by both client and server.
It does not load subdirectories. If the directory contains JSON files that are not (valid) service definitions, the node will fail to start.

Clients
*******

Clients will periodically query the Discovery Service for new registrations.
Applications can then search for entries in the Discovery Service (in this case ``coffeecorner``), e.g.:

.. code-block:: text

    GET /internal/discovery/v1/discovery/coffeecorner/?credentialSubject.name=John%20Doe

Any string property in the Verifiable Credential(s) can be queried, including nested properties.
Arrays, numbers or booleans are not supported. Wildcards can be used to search for partial matches, e.g. ``Hospital*`` or ``*First``.
If multiple query parameters are specified, all of them must match a single Verifiable Credential.

Registration
============

To register a DID on a Discovery Service, the DID must be activated for the service.
The Nuts node will then register a Verifiable Presentation of the DID on the service, and periodically refresh it.
E.g., for service ``coffeecorner`` and DID ``did:web:example.com``:

.. code-block:: text

    POST /internal/discovery/v1/coffeecorner/did:web:example.com

The DID's wallet must contain the Verifiable Credential(s) that are required by the service definition,
otherwise registration will fail. If the wallet does not contain the credentials,
the Nuts node will retry registration periodically.

Servers
*******
To act as server for a specific discovery service, its service ID needs to be specified in ``discovery.server.ids``, e.g.:

.. code-block:: yaml

    discovery:
      server:
        ids:
          - "coffeecorner"

The IDs in this list must correspond to the ``id`` fields of the loaded service definition, otherwise the node will fail to start.

Clients will access the discovery service through ``/discovery`` on the external HTTP interface, so make sure it's available externally.

The endpoint for a Discovery Service MUST be in the following form (unless mapped otherwise in a reverse proxy):

.. code-block:: text

    https://<host>/discovery/<service_id>

Where ``<service_id>`` is the ID of the service, e.g.: ``/discovery/coffeecorner``.