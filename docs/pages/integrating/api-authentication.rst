.. _nuts-node-api-authentication:

API Authentication
==================
The Nuts node's ``/internal`` HTTP endpoints can be configured to require signed JWT tokens before allowing calls.

When enabled you need to pass a bearer token as ``Authorization`` header:

    Authorization: Bearer (token)

When authentication fails the API will return ``HTTP 401 Unauthorized``. The logs on the nuts-node will provide
an explanation about the failure.

.. note::

    The JWTs and private keys used in this authentication scheme are secrets and should never be shared with anyone. No one should ever ask you to send them your JWTs or private keys.

Configuration
-------------
Authentication can be enabled by setting ``http.internal.auth.type`` (see example above) to ``token_v2``.
Endpoints under ``/internal`` will then require a JWT signed by an authorized key.

Authorized (public) keys are specified in an ``authorized_keys`` file configured by the ``http.internal.auth.type.authorizedkeyspath`` parameter.
This file should contain one or more trusted keys, in the standard SSH format. ECDSA, Ed25519, and RSA (>=2048-bit) keys
are accepted. Each line in the file must contain the key-type, key-specification, and user name that is authorized,
for example ``ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH1VNKtThJiI6c5zjLn/6EjRq1PtfM4qw4HM71zivIVn john.doe@company.com``.
Note that this file should be a distinct ``authorized_keys`` file from that used to grant console access to the
nuts node. API access and SSH access are two entirely different matters and we are simply using this well known
configuration file format. The Nuts node does not integrate in any way with the SSH subsystem on the host OS.

.. code-block:: yaml

    http:
      internal:
        auth:
          type: token_v2                                 # enables authentication
          authorizedkeyspath: /opt/nuts/authorized_keys  # path to the file containing public keys that are allowed to authenticate.
                                                         # JWTs must be signed with a key registered in this file,
          audience: nuts-node.example.com                # audience for the JWT, defaults to the machine's host name

JWT requirements
----------------

JWT's can be generated in code and must meet the following requirements:

* The ``iss`` field must be present
* The ``iss`` field must match the username specified in the comment of an ``authorized_keys`` entry
* The ``sub`` field must be present and non-empty (set it to the issuer if you are unsure which value to use)
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

The following entries MUST NOT be present:

* The ``jwk`` field (embeds the public key)
* The ``jku`` field (embeds a URL for fetching the public key)
* The ``x5c`` field (embeds an X.509 certificate chain,)
* The ``x5u`` field (embeds a URL for fetching the public key in X.509 form)

Implementing API Authentication
-------------------------------

Generally speaking for your application to access the protected API endpoints the following process must be followed:

1. Generate a private Ed25519, ECDSA, or RSA (>=2048-bit) key. Use Ed25519 if unsure which type to use.
2. Generate an ``authorized_keys`` entry for your public key and configure the Nuts node with it (see below).
3. Create a JWT, meeting the above specifications
4. Sign the JWT using the key generated in step 1.
5. Include the encoded JWT as a bearer token in the ``Authorization`` header of API requests.
6. Stop using the JWT before it expires, rotating it for a freshly generated JWT.
7. Be careful to keep your JWTs out of log messages etc., and treat them as secret at all times.

The following events are audited concerning API authentication:
- ``AccessKeyRegistered`` for each authorized key, on startup.
- ``AccessDenied`` when a JWT fails to authenticate.
- ``AccessGranted`` when a JWT successfully authenticates.

Generating ``authorized_keys`` file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``authorized_keys`` files are made up of multiple lines, each line specifying one more key/user that is authorized. For more information on the authorized_keys format see the ``AUTHORIZED_KEYS FILE FORMAT`` section of the `man page <http://man.he.net/man5/authorized_keys>`_.

The following is an example ``authorized_keys`` file. Each line specifies the key type, the public key, and the username:

 .. code-block::

    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAPwLGkaO5dWEx29sW4xnmv/s8+Nzj3mnkY6SX9Qnb91oyPayZV8Ts3TXSMKlkyYHVcIz/nAxRgxgKBTMwZc2wE= alice@company.com
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAwaOa7iN1gnKEfiZAA7lhu3SIvfdzYE3VbswsVUQP7F bob@company.com
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH1VNKtThJiI6c5zjLn/6EjRq1PtfM4qw4HM71zivIVn dan@company.com
    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC54Az33UVYdRSTb/2N9LiZtL7TRiEox5+rJcnMYz+t30l4UG5Y8ZN6L2dJCCFWyQeeJ/oTOY915L9/miklDyhk= heidi@company.com

To generate a key's authorized_keys form using ssh-keygen:
 .. code-block:: shell

    ssh-keygen -y -f /path/to/keyfile

Generating ``kid`` field
^^^^^^^^^^^^^^^^^^^^^^^^

You can use ``ssh-keygen`` to generate the SSH fingerprint (used in the ``kid`` field) of a key:

 .. code-block:: shell

    ssh-keygen -lf /path/to/keyfile

nuts-jwt-generator
------------------

The nuts-jwt-generator is a command-line tool that can be used to generate JWTs and authorized_keys entries.
For instance, when ``ssh-keygen`` is unavailable on your platform or when using Ed25519 keys (see below).
It is available on the nuts-foundation `GitHub page <https://github.com/nuts-foundation/jwt-generator>`_.

To generate a key's authorized_keys form (for configuration of the Nuts node) using nuts-jwt-generator:

.. code-block:: shell

    nuts-jwt-generator -i /path/to/keyfile --export-authorized-key

To generate the SSH fingerprint of a key (for specifying as ``kid`` field) using nuts-jwt-generator:

.. code-block:: shell

    nuts-jwt-generator -i /path/to/keyfile -export-ssh-fingerprint

The ``ssh-keygen``` command unfortunately fails for Ed25519 PEM keys at the time of this writing due to a `bug <https://bugzilla.mindrot.org/show_bug.cgi?id=3195>`_ and poor recent support for Ed25519 in libcrypto packages.
You can use the nuts-jwt-generator until this bug is fixed for keys of this type.

Generating keys
---------------

Just for reference, this section lists various commands to generate key pairs for signing JWTs, using ``ssh-keygen`` and ``openssl``.

To generate an ECDSA key using ssh-keygen:

 .. code-block:: shell

    ssh-keygen -t ecdsa -b 521 -f /path/to/keyfile

To generate an RSA key using ssh-keygen:

 .. code-block:: shell

    ssh-keygen -t rsa -b 4096 -f /path/to/keyfile

To generate an Ed25519 key with using ssh-keygen:

 .. code-block:: shell

    ssh-keygen -t ed25519 -f /path/to/keyfile

To generate an ECDSA key with OpenSSL:

 .. code-block:: shell

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -pkeyopt ec_param_enc:named_curve -out /path/to/keyfile.pem

To generate an RSA key with OpenSSL:

 .. code-block:: shell

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out /path/to/rsa-private.pem

To generate an Ed25519 key with OpenSSL:

 .. code-block:: shell

    openssl genpkey -algorithm ed25519 -out /path/to/keyfile.pem
