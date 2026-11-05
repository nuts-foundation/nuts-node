.. _discovery:

Discovery
#########

This implements `Nuts RFC022 Discovery Service <https://nuts-foundation.gitbook.io/drafts/rfc/rfc022-discovery-service>`_.

Discovery allows parties to publish information about themselves as a Verifiable Presentation,
so that other parties can discover them for further (data) exchange.
A Discovery Service is hosted on a server (also a Nuts node) and defined by a service definition, agreed upon by the parties of a use case.

How to write a service definition, and how to register and search through the API, is described on the wiki:

- `Service Discovery <https://wiki.nuts.nl/books/designing-a-nuts-use-case/page/service-discovery>`_ (designing a use case)
- `Register on the Discovery Service <https://wiki.nuts.nl/books/implementing-a-nuts-v2-use-case/page/register-on-the-discovery-service>`_ and
  `Find care organizations and their endpoints <https://wiki.nuts.nl/books/implementing-a-nuts-v2-use-case/page/find-care-organizations-and-their-endpoints>`_ (implementing a use case)

Service definitions
*******************

Service definitions are loaded from the ``discovery.definitions.directory`` directory by both client and server.
It does not load subdirectories. If the directory contains JSON files that are not (valid) service definitions, the node will fail to start.

Registered Verifiable Presentations may be at most 64 KiB. This is a fixed limit of the Nuts node, not configurable per service definition.

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
