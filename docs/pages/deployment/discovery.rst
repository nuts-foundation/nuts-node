.. _discovery:

Discovery
#########

This implements `Nuts RFC022 Discovery Service <https://nuts-foundation.gitbook.io/drafts/rfc/rfc022-discovery-service>`_.

Discovery allows parties to publish information about themselves as a Verifiable Presentation,
so that other parties can discover them for further (data) exchange.
A Discovery Service is hosted on a server (also a Nuts node) and defined by a service definition, agreed upon by the parties of a use case.

How to write a service definition, and how to register and search through the API, is described on the wiki:

- `Service Discovery <https://wiki.nuts.nl/link/87>`_ (designing a use case)
- `Register on the Discovery Service <https://wiki.nuts.nl/link/146>`_ and
  `Find care organizations and their endpoints <https://wiki.nuts.nl/link/152>`_ (implementing a use case)

Service definitions
*******************

Service definitions are loaded from the ``discovery.definitions.directory`` directory by both client and server.
It does not load subdirectories. If the directory contains JSON files that are not (valid) service definitions, the node will fail to start.

Example:

.. code-block:: json

   {
      "id": "coffeecorner",
      "did_methods": ["web", "nuts"],
      "endpoint": "https://example.com/discovery/coffeecorner",
      "presentation_max_validity": 36000,
      "presentation_definition": {
        "id": "coffeecorner2024",
        "format": {
          "ldp_vc": {
            "proof_type": [
              "JsonWebSignature2020"
            ]
          },
          "jwt_vp": {
            "alg": ["ES256"]
          }
        },
        "input_descriptors": [
          {
            "id": "NutsOrganizationCredential",
            "constraints": {
              "fields": [
                {
                  "path": [
                    "$.type"
                  ],
                  "filter": {
                    "type": "string",
                    "const": "NutsOrganizationCredential"
                  }
                },
                {
                  "path": [
                    "$.credentialSubject.organization.name"
                  ],
                  "filter": {
                    "type": "string"
                  }
                },
                {
                  "path": [
                    "$.credentialSubject.organization.city"
                  ],
                  "filter": {
                    "type": "string"
                  }
                }
              ]
            }
          }, {
            "id": "DiscoveryRegistrationCredential",
            "constraints": {
              "fields": [
                {
                  "id":   "auth_server_url",
                  "path": [
                    "$.credentialSubject.authServerURL"
                  ]
                }
              ]
            }
          }
        ]
      }
    }

A service definition is a JSON object with the following fields:

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Field
     - Required
     - Description
   * - ``id``
     - yes
     - Unique identifier of the Discovery Service (non-empty string).
       It is used in the API paths (``/internal/discovery/v1/<id>``), in ``discovery.server.ids``,
       and as the audience (``aud``) of registered Verifiable Presentations.
       Two loaded definitions with the same ``id`` make the node fail to start.
   * - ``did_methods``
     - no
     - DID methods allowed on the service, without the ``did:`` prefix (e.g. ``web``, ``nuts``).
       A client only registers the subject's DIDs that use one of these methods; the server rejects presentations signed by other DID methods.
       Empty or missing means all DID methods are allowed.
   * - ``endpoint``
     - yes
     - URL of the Discovery Server (non-empty string). Clients register and fetch presentations here.
       See `Servers`_ for its form.
   * - ``presentation_max_validity``
     - yes
     - Maximum validity of a registered Verifiable Presentation, in seconds (integer, at least 1).
       The server rejects presentations that are valid for longer.
       A client creates presentations valid for this long and refreshes its registration after 45% of it.
   * - ``presentation_definition``
     - yes
     - `Presentation Definition <https://identity.foundation/presentation-exchange/>`_ the credentials in a registration must match.
       It is validated against the Presentation Exchange v2 JSON schema.
       See below for how the Nuts node uses it.

How the Nuts node uses the ``presentation_definition``:

- ``format`` limits which credential formats match. Registered presentations are always JWT Verifiable Presentations.
- Constraint fields with an ``id`` are returned in the ``fields`` of search results, keyed by that ``id`` (``auth_server_url`` in the example above).
- Registration parameters (given when activating a subject) are put in the ``credentialSubject`` of a ``DiscoveryRegistrationCredential``.
  They are only included in the registration if the Presentation Definition has an input descriptor for that credential;
  a parameter is matched with the path ``$.credentialSubject.<name>``.
  The Nuts node always adds ``authServerURL`` (``https://<url>/oauth2/<subject>``, where ``<url>`` is the node's ``url`` config).

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
