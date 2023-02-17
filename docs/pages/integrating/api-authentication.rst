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

Handle With Care
================

The JWTs and private keys used in this authentication scheme are secrets and should never be shared with anyone. No one should ever ask you to send them your JWTs or private keys.

nuts-jwt-generator
==================

Tokens can be generated using the ``nuts-jwt-generator`` command, available on the nuts-foundation `GitHub page <https://github.com/nuts-foundation/jwt-generator>`_.

JWT Generation in Code
======================

JWT's can be generated in code and must meet the following requirements:
* The ``iss`` field must be present
* The ``sub`` field must be present
* The ``sub`` field must match the username specified in the comment of an ``authorized_keys`` entry
* The ``iat`` field must be present
* The ``nbf`` field must be present
* The ``iat`` value must occur at or before the ``nbf`` value
* The ``exp`` field must be present
* The ``exp`` value must occur no more than 24 hours after the ``iat`` value
* The ``jti`` field must be present and contain a `UUID <https://en.wikipedia.org/wiki/Universally_unique_identifier>`_ string
* The ``aud`` field must be present
* The ``aud`` field must contain the configured ``auth.audience`` parameter (hostname by default) on the nuts node
* The JWT must be signed by a known ECDSA, Ed25519, or RSA (>=2048-bit) key as configured in ``auth.authorizedkeyspath``
* Signatures based on RSA keys may use the RS512 or PS512 algorithms only
* The ``kid`` field must contain either the `JWK SHA-256 Thumbprint <https://www.rfc-editor.org/rfc/rfc7638>`_ (e.g. ``NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs``) or the `SSH SHA-256 fingerprint <https://www.ietf.org/rfc/rfc4253.txt>`_ (e.g. ``SHA256:G5hwd24Zl7dyTsAGVxqyZk6z+oJ5UxWcIRL3fWGj7wk``) of the signing key
* The JWT must not be encrypted

Libraries
---------

Libraries for generating JSON Web Tokens are `available for all major programming languages <https://jwt.io/libraries>`_.

Calling Application Requirements
--------------------------------
Generally speaking for your application to access the protected API endpoints the following process must be followed:
1. Generate a private Ed25519, ECDSA, or RSA (>=2048-bit) key. Use Ed25519 if unsure which type to use.
2. Generate an ``authorized_keys`` entry for your public key and configure the nuts-node with it. See :ref:`Configuring for Production <production-configuration>`.
3. Create a JWT, meeting the above specifications
4. Sign the JWT using the key generated in step 1.
5. Include the encoded JWT as a bearer token in the ``Authorization`` header of API requests.
6. Stop using the JWT before it expires, rotating it for a freshly generated JWT.
7. Be careful to keep your JWTs out of log messages etc., and treat them as secret at all times.

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
