nuts-node
#########

Open-source implementation of did:web, OpenID4VC, PEX, private key management and related logic.
It enables secure and trusted data exchange between organizations.
It contains all the necessary components for secure discovery and authorization.

See the `documentation <https://nuts-node.readthedocs.io/en/stable/>`_ for how to set up, integrate and use the Nuts node.

.. image:: https://github.com/nuts-foundation/nuts-node/actions/workflows/go-test.yaml/badge.svg
    :target: https://github.com/nuts-foundation/nuts-node/actions/workflows/go-test.yaml
    :alt: Build Status

.. image:: https://readthedocs.org/projects/nuts-node/badge/?version=latest
    :target: https://nuts-node.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://qlty.sh/gh/nuts-foundation/projects/nuts-node/coverage.svg
    :target: https://qlty.sh/gh/nuts-foundation/projects/nuts-node
    :alt: Code coverage

.. image:: https://qlty.sh/gh/nuts-foundation/projects/nuts-node/maintainability.svg
    :target: https://qlty.sh/gh/nuts-foundation/projects/nuts-node
    :alt: Maintainability

.. image:: https://github.com/nuts-foundation/nuts-node/actions/workflows/build-images.yaml/badge.svg
    :target: https://github.com/nuts-foundation/nuts-node/actions/workflows/build-images.yaml
    :alt: Build Docker images

.. image:: https://img.shields.io/badge/-Nuts_Community-informational?labelColor=grey&logo=slack
    :target: https://join.slack.com/t/nuts-foundation/shared_invite/zt-19av5q5ur-5fNbZVIFGUw5vDKSy5mqCw
    :alt: Nuts Community on Slack

Contributing
^^^^^^^^^^^^

See `COLLABORATORS.md <COLLABORATORS.md>`_ for how to contribute.

For AI-agentic Maintainers
^^^^^^^^^^^^^^^^^^^^^^^^^^

(and maybe for some human maintainers as well):

Claude Code skill files for common maintenance tasks can be found in the `.claude/commands directory <.claude/commands>`_.

Development
^^^^^^^^^^^

See `DEVELOPMENT.md <DEVELOPMENT.md>`_ for build, test and code generation instructions.

Configuration
^^^^^^^^^^^^^

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

.. list-table:: Server Options
    :widths: 20 30 50
    :class: options-table
    :header-rows: 1

    * - Key
      - Default
      - Description
    * - configfile
      - ./config/nuts.yaml
      - Nuts config file
    * - cpuprofile
      -
      - When set, a CPU profile is written to the given path. Ignored when strictmode is set.
    * - datadir
      - ./data
      - Directory where the node stores its files.
    * - didmethods
      - [web,nuts]
      - Comma-separated list of enabled DID methods (without did: prefix). It also controls the order in which DIDs are returned by APIs, and which DID is used for signing if the verifying party does not impose restrictions on the DID method used.
    * - internalratelimiter
      - true
      - When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode.
    * - loggerformat
      - text
      - Log format (text, json)
    * - strictmode
      - true
      - When set, insecure settings are forbidden.
    * - url
      -
      - Public facing URL of the server (required). Must be HTTPS when strictmode is set. It's baked into every DID and OAuth identity the node issues, so choose a domain you own, that is stable (avoid TLDs that block re-registration after expiry, and cloud-provider subdomains that don't identify the owner), and that serves security.txt and robots.txt at its root.
    * - verbosity
      - info
      - Log level (trace, debug, info, warn, error)
    * - httpclient.timeout
      - 30s
      - Request time-out for HTTP clients, such as '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.
    * - **Auth**
      -
      -
    * - auth.authorizationendpoint.enabled
      - false
      - enables the v2 API's OAuth2 Authorization Endpoint, used by OpenID4VP and OpenID4VCI. This flag might be removed in a future version (or its default become 'true') as the use cases and implementation of OpenID4VP and OpenID4VCI mature.
    * - auth.experimental.jwtbearerclient
      - false
      - enables the experimental RFC 7523 jwt-bearer two-VP token request flow. While disabled (the default), requests carrying a service-provider subject identifier are rejected. Subject to change without notice.
    * - **Crypto**
      -
      -
    * - crypto.storage
      -
      - Storage to use, 'fs' for file system (for development purposes), 'vaultkv' for HashiCorp Vault KV store, 'azure-keyvault' for Azure Key Vault, 'external' for an external backend (deprecated).
    * - crypto.azurekv.hsm
      - false
      - Whether to store the key in a hardware security module (HSM). If true, the Azure Key Vault must be configured for HSM usage. Default: false
    * - crypto.azurekv.timeout
      - 10s
      - Timeout of client calls to Azure Key Vault, in Golang time.Duration string format (e.g. 10s).
    * - crypto.azurekv.url
      -
      - The URL of the Azure Key Vault.
    * - crypto.azurekv.auth.type
      - default
      - Credential type to use when authenticating to the Azure Key Vault. Options: default, managed_identity (see https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/azidentity/README.md for an explanation of the options).
    * - crypto.vault.address
      -
      - The Vault address. If set it overwrites the VAULT_ADDR env var.
    * - crypto.vault.pathprefix
      - kv
      - The Vault path prefix.
    * - crypto.vault.timeout
      - 5s
      - Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 1s).
    * - crypto.vault.token
      -
      - The Vault token. If set it overwrites the VAULT_TOKEN env var.
    * - **Discovery**
      -
      -
    * - discovery.client.refreshinterval
      - 10m0s
      - Interval at which the client synchronizes with the Discovery Server; refreshing Verifiable Presentations of local DIDs and loading changes, updating the local copy. It only will actually refresh registrations of local DIDs that about to expire (less than 1/4th of their lifetime left). Specified as Golang duration (e.g. 1m, 1h30m).
    * - discovery.definitions.directory
      - ./config/discovery
      - Directory to load Discovery Service Definitions from. If not set, the discovery service will be disabled. If the directory contains JSON files that can't be parsed as service definition, the node will fail to start.
    * - discovery.server.ids
      - []
      - IDs of the Discovery Service for which to act as server. If an ID does not map to a loaded service definition, the node will fail to start.
    * - **HTTP**
      -
      -
    * - http.clientipheader
      - X-Forwarded-For
      - Case-sensitive HTTP Header that contains the client IP used for audit logs. For the X-Forwarded-For header only link-local, loopback, and private IPs are excluded. Switch to X-Real-IP or a custom header if you see your own proxy/infra in the logs.
    * - http.log
      - metadata
      - What to log about HTTP requests. Options are 'nothing', 'metadata' (log request method, URI, IP and response code), and 'metadata-and-body' (log the request and response body, in addition to the metadata). In strictmode, 'metadata-and-body' is not allowed and is changed to 'metadata' at startup.
    * - http.cache.maxbytes
      - 10485760
      - HTTP client maximum size of the response cache in bytes. If 0, the HTTP client does not cache responses.
    * - http.client.allowedinternalcidrs
      - []
      - IP ranges (CIDR notation, e.g. 10.0.0.0/8) exempted from the strict-mode SSRF guard, which otherwise blocks outbound requests to non-public networks. Use to permit internal flows that legitimately target a private address, such as an internal credential offering or an internal OAuth user flow. Leave empty to block all non-public addresses.
    * - http.client.deniedcidrs
      - []
      - IP ranges (CIDR notation) that outbound HTTP requests must never target in strict mode, in addition to the built-in blocked ranges (non-public addresses and cloud metadata endpoints). Use for publicly routable ranges that are internal-only in your infrastructure. Takes precedence over http.client.allowedinternalcidrs.
    * - http.internal.address
      - 127.0.0.1:8081
      - Address and port the server will be listening to for internal-facing endpoints.
    * - http.internal.auth.audience
      -
      - Expected audience for JWT tokens (default: hostname)
    * - http.internal.auth.authorizedkeyspath
      -
      - Path to an authorized_keys file for trusted JWT signers
    * - http.internal.auth.type
      -
      - Whether to enable authentication for /internal endpoints, specify 'token_v2' for bearer token mode or 'token' for legacy bearer token mode.
    * - http.public.address
      - \:8080
      - Address and port the server will be listening to for public-facing endpoints.
    * - **JSONLD**
      -
      -
    * - jsonld.contexts.localmapping
      - [https://nuts.nl/credentials/2024=assets/contexts/nuts-2024.ldjson,https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://w3id.org/vc/status-list/2021/v1=assets/contexts/w3c-statuslist2021.ldjson,https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson]
      - This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist.
    * - jsonld.contexts.remoteallowlist
      - [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json,https://w3id.org/vc/status-list/2021/v1]
      - In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here.
    * - **PKI**
      -
      -
    * - pki.maxupdatefailhours
      - 4
      - Maximum number of hours that a denylist update can fail
    * - pki.softfail
      - true
      - Do not reject certificates if their revocation status cannot be established when softfail is true
    * - **Storage**
      -
      -
    * - storage.debug
      - false
      - When true, enables extra logging of storage-layer problems (e.g. performance issues).
    * - storage.session.memcached.address
      - []
      - List of Memcached server addresses. These can be a simple 'host:port' or a Memcached connection URL with scheme, auth and other options.
    * - storage.session.redis.address
      -
      - Redis session database server address. This can be a simple 'host:port' or a Redis connection URL with scheme, auth and other options. If not set it, defaults to an in-memory database.
    * - storage.session.redis.database
      -
      - Redis session database name, which is used as prefix every key. Can be used to have multiple instances use the same Redis instance.
    * - storage.session.redis.password
      -
      - Redis session database password. If set, it overrides the username in the connection URL.
    * - storage.session.redis.username
      -
      - Redis session database username. If set, it overrides the username in the connection URL.
    * - storage.session.redis.sentinel.master
      -
      - Name of the Redis Sentinel master. Setting this property enables Redis Sentinel.
    * - storage.session.redis.sentinel.nodes
      - []
      - Addresses of the Redis Sentinels to connect to initially. Setting this property enables Redis Sentinel.
    * - storage.session.redis.sentinel.password
      -
      - Password for authenticating to Redis Sentinels.
    * - storage.session.redis.sentinel.username
      -
      - Username for authenticating to Redis Sentinels.
    * - storage.session.redis.tls.truststorefile
      -
      - PEM file containing the trusted CA certificate(s) for authenticating remote Redis session servers. Can only be used when connecting over TLS (use 'rediss://' as scheme in address).
    * - storage.sql.connection
      -
      - Connection string for the SQL database. If not set it, defaults to a SQLite database stored inside the configured data directory. Note: using SQLite is not recommended in production environments. If using SQLite anyways, remember to enable foreign keys ('_foreign_keys=on') and the write-ahead-log ('_journal_mode=WAL').
    * - storage.sql.rdsiam.dbuser
      -
      - Database username for IAM authentication. If not specified, the username from the connection string will be used. The database user must be created with IAM authentication enabled.
    * - storage.sql.rdsiam.enabled
      - false
      - Enable AWS RDS IAM authentication for the SQL database connection. When enabled, the node will use temporary IAM tokens instead of passwords. Requires the connection string to be a PostgreSQL or MySQL RDS endpoint without a password.
    * - storage.sql.rdsiam.region
      -
      - AWS region where the RDS instance is located (e.g., 'us-east-1). Required when RDS IAM authentication is enabled.
    * - storage.sql.rdsiam.tokenrefreshinterval
      - 14m0s
      - Interval at which to refresh the IAM authentication token. RDS tokens are valid for 15 minutes, so set this to ensure tokens are refreshed before expiry. Specified as Golang duration (e.g. 10m, 1h).
    * - **Tracing**
      -
      -
    * - tracing.endpoint
      -
      - OTLP collector endpoint for OpenTelemetry tracing (e.g., 'localhost:4318'). When empty, tracing is disabled.
    * - tracing.insecure
      - false
      - Disable TLS for the OTLP connection.
    * - tracing.servicename
      -
      - Service name reported to the tracing backend. Defaults to 'nuts-node'.
    * - **policy**
      -
      -
    * - policy.directory
      - ./config/policy
      - Directory to read policy files from. Policy files are JSON files that contain a scope to PresentationDefinition mapping.
    * - policy.authzen.endpoint
      -
      - Base URL of the AuthZen PDP endpoint. Required when any credential profile uses scope_policy 'dynamic'; the node refuses to start if such a profile is configured but this flag is empty.

If your use case still uses ``did:nuts`` DIDs and/or the gRPC network, there's an additional (deprecated) options
table in :ref:`Legacy did:nuts configuration <legacy-did-nuts-configuration>`.

See :ref:`The node's URL <nuts-node-url>` for guidance on choosing the ``url`` option.

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

