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

Options specific for ``did:nuts``/gRPC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following table contains additional (deprecated) options that are relevant for use cases that use ``did:nuts`` DIDs and/or the gRPC network.
If your use case does not use these features, you can ignore this table.

.. include:: server_options_didnuts.rst

This table is automatically generated using the configuration flags in the core and engines. When they're changed
the options table must be regenerated using the Makefile:

.. code-block:: shell

    $ make docs

.. _node-http-services-baseurl:

Registering ``node-http-services-baseurl``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``did:nuts`` DIDs receive private Verifiable Credentials over OpenID4VCI: a synchronous HTTP push, from the issuer's node directly to the holder's node, at issuance time.
For a node to be reachable this way (as issuer or holder), its ``did:nuts`` DID document needs a ``node-http-services-baseurl`` service, pointing other nodes at the public base URL where its OpenID4VCI (and other ``/n2n``) HTTP endpoints can be reached.
Without it, the node can't be discovered over OpenID4VCI: offers to it fail, and offers from it fall back to the deprecated gRPC/Nuts network, or fail outright if that's disabled too.

This service is **not** registered automatically.
GoldenHammer (a background module that periodically fixes a handful of common DID document issues) will add it if it detects it's missing, but GoldenHammer is scheduled for removal once OpenID4VCI becomes the only way to exchange credentials
(see `issue #2318 <https://github.com/nuts-foundation/nuts-node/issues/2318>`_) and, being a periodic best-effort fix, can't guarantee the service is present the moment it's actually needed.
Register it explicitly as part of node setup, the same way the required ``NutsComm`` service is registered, using the DIDMan API's endpoint:

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

If a node's own DID document is missing this service, its log will show a warning like ``Local DID document is not properly configured for OpenID4VCI issuance``, naming the affected DID.

Secrets
*******

All options ending with ``token`` or ``password`` are considered secrets and can only be set through environment variables or the config file.

Strict mode
***********

Several of the server options above allow the node to be configured in a way that is unsafe for production environments, but are convenient for testing or development.
The node can be configured to run in strict mode (default) to prevent any insecure configurations.
Below is a summary of the impact ``strictmode=true`` has on the node and its configuration.

Save storage of any private key material and data requires some serious consideration.
For this reason the ``crypto.storage`` backend and the ``storage.sql.connection`` connection string must explicitly be set.

Private transactions can only be exchanged over authenticated nodes.
Therefore is requires TLS to be configured through ``tls.{certfile,certkeyfile,truststore}``.
To verify that authentication is correctly configured on your node, check the ``network.auth_config`` status on the ``/health`` endpoint.
See :ref:`Monitoring <nuts-node-monitoring>` for more details.

The incorporated `IRMA server <https://irma.app/docs/irma-server/#production-mode>`_ is automatically changed to production mode.
In fact, running in strict mode is the only way to enable IRMA's production mode.
In addition, it requires ``auth.irma.schememanager=pbdf``.

As a general safety precaution ``auth.contractvalidators`` ignores the ``dummy`` option if configured,
requesting an access token from another node on ``/n2n/auth/v1/accesstoken`` does not return any error details,
``auth.accesstokenlifespan`` is always 60 seconds,
json-ld context can only be downloaded from trusted domains configured in ``jsonld.contexts.remoteallowlist``,
``http.log=metadata-and-body`` is not allowed and is changed to ``metadata`` at startup (request and response bodies on the OAuth endpoints contain credentials, which must not be written to logs),
and the ``internalratelimiter`` is always on.

Interacting with remote Nuts nodes requires HTTPS: it will refuse to connect to plain HTTP endpoints when in strict mode.
Strict mode additionally rejects outbound URLs whose host is an RFC 2606 reserved hostname/TLD (e.g. ``*.localhost``, ``*.test``, ``example.com/net/org``); non-public IP addresses are refused too, unless explicitly permitted via ``http.client.allowedinternalcidrs``.
This applies to every outbound HTTP call made via the shared HTTP client (OpenID4VCI, OAuth relying-party, IAM, Discovery, did:web resolution, etc.) and to every redirect target along the way.