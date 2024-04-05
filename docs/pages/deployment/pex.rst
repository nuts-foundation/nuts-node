.. _pex:

Presentation Definition mapping
###############################

Wallet functionality uses `Presentation Definitions <https://identity.foundation/presentation-exchange/>`_ to determine the required credentials for a given presentation request.
An OAuth2 authorization request uses scopes to determine the required permissions for a given request.
The mapping between scopes and presentation definitions is defined in a configuration file or by a policy backend.

Configuration
*************

The Nuts config supports two ways to define the mapping between OAuth2 scopes and presentation definitions:
- using a file-based configuration
- using a policy backend

The file-based configuration is a simple way to define the mapping between scopes and presentation definitions.
It can be used for simple use cases where the mapping is static and does not change often.

To use file-based configuration, you need to define the path to a directory that contains policy configuration files:

.. code-block:: yaml

    policy:
        directory: /path/to/directory

All JSON files in the directory will be loaded and used to define the mapping between scopes and presentation definitions.

To use a policy backend, you need to add the address of the policy backend to the configuration:

.. code-block:: yaml

	policy:
		address: http://localhost:8080

You cannot define both the directory and the address in the configuration. If both are defined, an error will be raised at startup.

File-based configuration
************************

JSON files used for file-based configuration must have the following structure:

.. code-block:: json

	{
		"example_scope": {
			"organization": {
				"id": "example",
				"format": {
					"ldp_vc": {
						"proof_type": ["JsonWebSignature2020"]
					},
					"ldp_vp": {
						"proof_type": ["JsonWebSignature2020"]
					}
				},
				"definition": {
					"input_descriptors": [
						{
							"id": "1",
							"constraints": {
								"fields": [
									{
										"path": ["$.type"],
										"filter": {
											"type": "string",
											"const": "ExampleCredential"
										}
									}
								]
							}
						}
					]
				}
			}
		}
	}

Where `example_scope` is the scope that the presentation definition is associated with.
The `presentation_definition` object contains the presentation definition that should be used for the given scope.
The `wallet_owner_type` field is used to determine the audience type of the presentation definition, valid values are `organization` and `user`.

Policy backend API definition
*****************************

The policy backend API is defined in the `OpenAPI 3.x <https://spec.openapis.org/oas/latest.html>`_ format.
The API must have the following endpoint:

- `GET /presentation_definitions?scope=X&authorizer=Y`: Get the presentation definition for a given scope and tenant.

The full API definition can be downloaded `here <../../_static/policy/v1.yaml>`_.

.. note::

	Using a policy backend relies on an architecture where the system checking the access token is responsible for enfocing access.
    It does not have to use the ``/authorized`` endpoint and can use a mechanism of its choice to check the permissions.
	The ``/authorized`` endpoint does give an idea on the information that is needed to check the permissions.