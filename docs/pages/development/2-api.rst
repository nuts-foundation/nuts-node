.. _api-dev:

API development
###############

When developing APIs, please follow these guidelines.

Contract first
**************

The Nuts node APIs are specified in `Open API Specification (OAS)<https://swagger.io/specification/>`_.
The files are located under ``/docs/_static/<engine>/<version>.yaml``.
Where ``<engine>`` is a specific module like ``crypto`` or ``auth`` and ``<version>`` defines the version of the API.
We use version ``3.0.y`` of the OAS.

Versioning
==========

We use versioning of the APIs.
This is reflected in both the OAS files and the HTTP paths.
Versions must follow the pattern ``v`` and start at ``v1``.
These are major versions, any breaking change results in a new major version of the API.
New additions, bug fixes and changes that are backwards compatible may be done in the current version.

Code generation
===============

The OAS files are used for code generation. The makefile contains the ``gen-api`` target which will generate the code.
The build target only needs to be extended when a new version or new engine is added.
Generated code is always placed in ``/<engine>/api/<version>/generated.go``.

Return codes
============

The error return values are generalized for all API calls.
The return values follow `RFC7807 <https://tools.ietf.org/html/rfc7807>`_.
The definition is available under ``/docs/_static/common/error_response.yaml``.
The error definition can be used in a OAS file:

.. code-block:: yaml

    paths:
        /some/path:
            get:
                responses:
                    default:
                      $ref: '../common/error_response.yaml'

The error responses will not be listed as responses in the online generated documentation.
To describe error responses, the specific responses need to be added to the API description:

.. code-block:: yaml

    paths:
        /some/path:
            post:
                description: |
                    Some description on the API

                    error returns:
                    * 400 - incorrect input

Paths
*****

The API paths are designed so different security schemes can be setup easily.

API paths follow the following pattern:

.. code-block:: text

    /<context>/<engine>/<version>/<action>

All paths start with a security ``<context>``:

- ``/internal/**`` These APIs are meant to be behind a firewall and should only be available to the internal infrastructure.
  All DID Document manipulation APIs fall under this category.
- ``/n2n/**`` These APIs must be available to other nodes from the network.
  This means they must be protected with the required client certificate as specified by `RFC011 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc011-verifiable-credential>`_.
  The creation of an access token is one example of such an API.
- ``/public/**`` These APIs must be publicly available on a valid domain. No security must be set.
  These APIs are used by mobile devices.

After the context, the ``<engine>`` is expected. An engine defines a logical unit of functionality.
Each engine has its own OAS file. Then as discussed earlier, the ``<version>`` is expected.
The last part is the ``<action>``, this part can be freely chosen in a RESTful manor.
