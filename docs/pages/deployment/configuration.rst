.. _nuts-node-config:

Configuration
#############

.. marker-for-readme

The Nuts node can be configured using a YAML configuration file, environment variables and commandline params.

The parameters follow the following convention:
``$ nuts --parameter X`` is equal to ``$ NUTS_PARAMETER=X nuts`` is equal to ``parameter: X`` in a yaml file.

Or for this piece of yaml

.. code-block:: yaml

    nested:
        parameter: X

is equal to ``$ nuts --nested.parameter X`` is equal to ``$ NUTS_NESTED_PARAMETER=X nuts``

Config parameters for engines are prepended by the ``engine.ConfigKey`` by default (configurable):

.. code-block:: yaml

    engine:
        nested:
            parameter: X

is equal to ``$ nuts --engine.nested.parameter X`` is equal to ``$ NUTS_ENGINE_NESTED_PARAMETER=X nuts``

While most options are a single value, some are represented as a list (indicated with the square brackets in the table below).
To provide multiple values through flags or environment variables you can separate them with a comma (``var1,var2``).
If you need to provide an actual value with a comma, you can escape it with a backslash (``\,``) to avoid it having split into multiple values.

Ordering
********

Command line parameters have the highest priority, then environment variables, then parameters from the configfile and lastly defaults.
The location of the configfile is determined by the environment variable ``NUTS_CONFIGFILE`` or the commandline parameter ``--configfile``. If both are missing the default location ``./nuts.yaml`` is used. ::

    CLI > ENV > Config File > Defaults

Server options
**************

The following options can be configured on the server:

.. marker-for-config-options

.. include:: server_options.rst

This table is automatically generated using the configuration flags in the core and engines. When they're changed
the options table must be regenerated using the Makefile:

.. code-block:: shell

    $ make docs

Secrets
*******

All options ending with ``token`` or ``password`` are considered secrets and can only be set through environment variables or the config file.

Strict mode
***********

Several of the server options above allow the node to be configured in a way that is unsafe for production environments, but are convenient for testing or development.
The node can be configured to run in strict mode (default) to prevent any insecure configurations.
Below is a summary of the impact ``strictmode=true`` has on the node and its configuration.

Save storage of any private key material requires some serious consideration.
For this reason the ``crypto.storage`` backend must explicitly be set.

Private transactions can only be exchanged over authenticated nodes.
Therefore strict mode requires ``network.enabletls=true``, and the certificate chain ``tls.{certfile,certkeyfile,truststore}`` must be provided.
To verify that authentication is correctly configured on your node, check the ``network.auth_config`` status on the ``/health`` endpoint.
See :ref:`getting started <configure-node>` on how to set this up correctly.

The incorporated `IRMA server <https://irma.app/docs/irma-server/#production-mode>`_ is automatically changed to production mode.
In fact, running in strict mode is the only way to enable IRMA's production mode.
In addition, it requires ``auth.irma.schememanager=pbdf`` and the ``auth.publicurl`` where the IRMA client can reach the server must be set.

As a general safety precaution ``auth.contractvalidators`` ignores the ``dummy`` option if configured,
requesting an access token from another node on ``/n2n/auth/v1/accesstoken`` does not return any error details,
``auth.accesstokenlifespan`` is always 60 seconds, ``http.default.cors.origin`` does not allow a wildcard (``*``),
json-ld context can only be downloaded from trusted domains configured in ``jsonld.contexts.remoteallowlist``,
and the ``internalratelimiter`` is always on.

Interacting with remote Nuts nodes requires HTTPS: it will refuse to connect to plain HTTP endpoints when in strict mode.

.. _node-http-services-baseurl:

Registering ``node-http-services-baseurl``
********************************************

``did:nuts`` DIDs receive private Verifiable Credentials via server-to-server issuance: the issuer's node pushes the credential directly to the holder's node over HTTP, at issuance time.
If a node can't be reached for server-to-server issuance, delivery falls back to the older gRPC/Nuts network instead: it publishes a transaction (with the recipient list encrypted) referencing the credential to the whole network, and the holder fetches the actual credential separately over an authenticated connection - a mechanism we're moving away from in favor of server-to-server issuance.
For a node to be reachable for server-to-server issuance (as issuer or holder), its ``did:nuts`` DID document needs a ``node-http-services-baseurl`` service endpoint, pointing other nodes at the public base URL where its HTTP services (including server-to-server issuance, and other ``/n2n`` endpoints) can be reached.
Without this DID Document service endpoint, its server-to-server issuance endpoints can't be discovered, triggering the gRPC fallback described above (or an outright failure if that's disabled too).
Given ``<base-url>`` and a DID, the endpoints it needs to be reachable at are:

- ``<base-url>/n2n/identity/<did>/.well-known/openid-credential-issuer`` - credential issuer metadata
- ``<base-url>/n2n/identity/<did>/.well-known/oauth-authorization-server`` - OAuth/provider metadata
- ``<base-url>/n2n/identity/<did>/openid4vci/credential`` - credential endpoint (issuer side)
- ``<base-url>/n2n/identity/<did>/openid4vci/credential_offer`` - credential offer endpoint (wallet/holder side)

This isn't an exhaustive list to configure individually: any reverse proxy or firewall in front of the node must forward the entire ``/n2n`` path prefix to it, not just these specific paths.

The DID Document service endpoint is added automatically when possible, to ease configuration: a background module, GoldenHammer, tests each hostname in the node's own TLS certificate with a ``HEAD`` request to ``https://<hostname>/n2n/identity/<did>/.well-known/openid-credential-issuer``, and registers the first hostname that responds with ``200 OK`` and ``Content-Type: application/json``.
This can fail if the node can't reach itself that way - DNS, firewall, and reverse-proxy routing are the usual suspects - in which case the endpoint stays missing.

You can also register the service endpoint manually via the DIDMan API, e.g. to have it in place immediately after setup rather than waiting for the next automatic check, or as a fallback if a subject DID's vendor reference can't be resolved automatically for any reason:

.. code-block:: shell

    $ curl -X POST https://internal.example.com/internal/didman/v1/did/<did>/endpoint \
        -H "Content-Type: application/json" \
        -d '{"type": "node-http-services-baseurl", "endpoint": "https://your-node.example.com"}'

For a vendor DID document (the one whose ``NutsComm`` service is a concrete URL, e.g. ``grpc://host:5555``), register the node's actual public base URL as the ``endpoint`` value, as above.

Any care-organization/subject DID document whose ``NutsComm`` service is instead a *reference* to that vendor DID should get a matching reference for ``node-http-services-baseurl``, rather than a duplicate concrete URL, so all subject DIDs of the same vendor stay in sync with a single registration:

.. code-block:: shell

    $ curl -X POST https://internal.example.com/internal/didman/v1/did/<subject-did>/endpoint \
        -H "Content-Type: application/json" \
        -d '{"type": "node-http-services-baseurl", "endpoint": "<vendor-did>/serviceEndpoint?type=node-http-services-baseurl"}'
