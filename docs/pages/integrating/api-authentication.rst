.. _nuts-node-api-authentication:

API Authentication
==================

JWT Token Authentication
************************

The Nuts Node's HTTP APIs can be configured to require signed JWT tokens before allowing calls.
Refer to :ref:`Configuring for Production <production-configuration>` to find out how to configure it.

When enabled you need to pass a bearer token as ``Authorization`` header:

    Authorization: Bearer (token)

When authentication fails the API will return ``HTTP 401 Unauthorized``. The logs on the nuts-node will provide
an explanation about the failure.

nuts-jwt-generator
==================

Tokens can be generated using the ``nuts-jwt-generator`` command, available on the nuts-foundation GitHub page.

Custom JWT Generation
=====================

Custom JWT's can be generated and must meet the following requirements:
* The iss field must be present
* The sub field must be present
* The iat field must be present
* The nbf field must be present
* The exp field must be present
* The iat value must occur before the nbf value
* The exp value must occur no more than 24 hours after the iat value
* The jti field must be present and contain a UUID string
* The aud field must be present
* The aud field must contain the configured ``auth.audience`` parameter (hostname by default) on the nuts node
* The JWT must be signed by a known ECDSA, Ed25519, or RSA (>=2048-bit) key as configured in ``auth.authorizedkeyspath``
* Signatures based on RSA keys may use the RS512 or PS512 algorithms only
* The kid field must contain the SSH SHA256 fingerprint (e.g. ``SHA256:G5hwd24Zl7dyTsAGVxqyZk6z+oJ5UxWcIRL3fWGj7wk``) of the corresponding public key
* The JWT must not be encrypted

Legacy Token Authentication
***************************

You can configure the Nuts Node's HTTP APIs to require legacy authentication before allowing calls.
Refer to :ref:`Configuring for Production <production-configuration>` to find out how to configure it.

When enabled you need to pass a bearer token as ``Authorization`` header:

    Authorization: Bearer (token)

You generate a token by using the ``http gen-token`` command.
The example below generates a token for a user named "admin", valid for 3 months:

.. code-block:: shell

    nuts http gen-token admin 90

When authentication fails the API will return ``HTTP 401 Unauthorized`` with an explanatory message.
