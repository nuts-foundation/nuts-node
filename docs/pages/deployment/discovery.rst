.. _discovery:

Discovery
#########

Discovery allows parties to publish information about themselves as a Verifiable Presentation,
so that other parties can discover them for further (data) exchange.

A Discovery Service is hosted on a server (also a Nuts node), by an organization that is agreed upon by the parties to be the server for that particular use case.
The parties implementing that use case then configure their Nuts nodes with the service definition that defines the server.

The service definition is a JSON document agreed upon (and loaded) by all parties that specifies:

- which Verifiable Credentials are required for the service,
- which DID methods are allowed (blank for all),
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

To register a subject on a Discovery Service, the subject must be activated for the service.
The Nuts node will then register a Verifiable Presentation for all subject DIDs on the service, and periodically refresh it.
E.g., for service ``coffeecorner`` and subject ``example``:

.. code-block:: text

    POST /internal/discovery/v1/coffeecorner/example

The wallet must contain the Verifiable Credential(s) that are required by the service definition,
otherwise registration will fail immediately.

Optionally, a POST body can be provided with registration parameters, e.g.:

.. code-block:: json

    {
      "registrationParameters": {
        "endpoint": "https://api.example.com",
        "contact": "alice@example.com"
      }
    }

This can be used to provide additional information. All registration parameters are returned by the search API.
The ``authServerURL`` is added automatically by the Nuts node. It's constructed as ``https://<config.url>/oauth2/<subject_id>``.

Once registered, future refreshes will be done automatically by the Nuts node. These refreshes could fail because of various reasons.
You can check the status of the refreshes by querying the service, e.g.:

.. code-block:: text

    GET /internal/discovery/v1/coffeecorner/example

The result contains a ``status`` field that indicates the status of the registration (``active`` or ``error``) . If the refresh fails, the ``error`` field contains the error message.

.. code-block:: json

    {
      "activated": true,
      "status": "error",
      "error": "error message",
      "vp": [...]
    }

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

Service definitions
*******************

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
          }
        ]
      }
    }


A service definition consists of:
- ``id``: the unique identifier of the service
- ``did_methods``: the DID methods that are allowed (optional)
- ``endpoint``: the URL of the service
- ``presentation_max_validity``: the maximum validity of the Verifiable Presentation in seconds
- ``presentation_definition``: the presentation definition that specifies the required Verifiable Credentials (see `Presentation Definitions <https://identity.foundation/presentation-exchange/>`_)

For details see `Nuts RFC022 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc022-discovery-service>`_.