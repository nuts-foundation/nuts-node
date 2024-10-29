.. _pex:

Presentation Definition mapping
###############################

Wallet functionality uses `Presentation Definitions <https://identity.foundation/presentation-exchange/>`_ to determine the required credentials for a given presentation request.
An OAuth2 authorization request uses scopes to determine the required permissions for a given request.
The mapping between scopes and presentation definitions is defined in a configuration file.

Configuration
*************

The Nuts config supports the mapping between OAuth2 scopes and presentation definitions using a file-based configuration.
The file-based configuration is a simple way to define the mapping between scopes and presentation definitions.
It can be used for simple use cases where the mapping is static and does not change often.

To use file-based configuration, you need to define the path to a directory that contains policy configuration files:

.. code-block:: yaml

    policy:
      directory: /path/to/directory

All JSON files in the directory will be loaded and used to define the mapping between scopes and presentation definitions.

Policy Structure
****************

JSON documents used for policies must have the following structure:

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
          "input_descriptors": [
            {
              "id": "1",
              "constraints": {
                "fields": [
                  {
                    "path": ["$.type"],
                    "filter": {
                      "type": "string",
                      "const": "HumanCredential"
                    }
                  },
                  {
                    "id": "fullName",
                    "path": ["$.credentialSubject.fullName"],
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
    }

Where ``example_scope`` is the scope that the presentation definition is associated with.
The ``presentation_definition`` object contains the presentation definition that should be used for the given scope.
The ``wallet_owner_type`` field is used to determine the audience type of the presentation definition, valid values are ``organization`` and ``user``.

OAuth2 Token Introspection field mapping
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The input descriptor constraint fields that contain an ``id`` property (``input_descriptor.contraints.field.id``) are returned in the OAuth2 Token Introspection response.
The value of the Verifiable Credential that the matched field is included in the response as claims.
E.g., in the example above, a claim named ``fullName`` is added to the introspection response, containing the value of the ``credentialSubject.fullName`` property in the Verifiable Credential.
The following is an example OAuth2 Token Introspection response containing the ``fullName`` claim from the Presentation Definition
(some fields are omitted for brevity):

.. code-block:: json

  {
    "iss": "did:web:example.com",
    "active": true,
    "scope": "example_scope",
    "fullName": "John Doe"
  }

If you want introspection to return part of a string, you can use the ``pattern`` regular expression filter in the field definition with a capture group.
Token introspection will return the value of the first capture group in the regular expression, instead of the full match, e.g.;
``{"role": "Admin level 4"}`` with the following pattern filter: ``"pattern": "Admin level ([0-9])"`` will return ``"role": "4"`` (given the field ID ``role``).

.. code-block:: json

  {
    "iss": "did:web:example.com",
    "active": true,
    "scope": "example_scope",
    "fullName": "John Doe"
  }

Writer of policies should take into consideration:
- fields that are intended to be used for logging or authorization decisions should have a distinct identifier.
- claims ideally map a registered claim name (e.g. `IANA JWT claims <https://www.iana.org/assignments/jwt/jwt.xhtml#claims>`_)
- overwriting properties already defined in the token introspection endpoint response is forbidden. These are: ``iss``, ``sub``, ``exp``, ``iat``, ``active``, ``client_id``, ``scope``.
