.. _nuts-node-config:

Options
#######

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

If your use case still uses ``did:nuts`` DIDs and/or the gRPC network, there's an additional (deprecated) options
table in :ref:`Legacy did:nuts configuration <legacy-did-nuts-configuration>`.

Choosing the node's URL
***********************

The ``url`` option is the node's public facing URL:

.. code-block:: yaml

    url: https://example.com

It's used in the following ways:

- It provides some information about the owner of DIDs and is part of the client_id in OAuth flows.
  Other parties can use it to identify your node.
- It's part of the DIDs the node creates for you when you create a new subject.
  For example: DID web URLs are constructed as ``did:web:<domain>:iam:<uuid>``.
- It's listed in OAuth metadata.
  For example: the default identity URL is ``https://<domain>/oauth2/<subject>``.
  This URL is then used to lookup .well-known endpoints.
- It's part of the URL for the StatusList2021 revocation mechanism.

There are no strict requirements for it, but please consider the following:

- You must own the domain.
- The domain should be stable. It should not change.
- It should use a TLD that allows for retention of the domain name.
  For example, a .com domain name can be blocked for a period of time after it's no longer registered.
  This will prevent the next owner from using it.
- The domain should be human readable.
  Sub-domains from cloud providers are not recommended since they don't provide information about the owner.
- There should be a security.txt and robots.txt file at the root of the domain.
  This is a best practice for security and privacy.

Once chosen, changing it is a disruptive operation; see :ref:`changing-base-url` for the procedure.

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