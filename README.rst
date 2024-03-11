nuts-node
#########

Open-source implementation of did:web, OpenID4VC, PEX, private key management and related logic.
It enables secure and trusted data exchange between organizations.
It contains all the necessary components for secure discovery and authorization.

See the `documentation <https://nuts-node.readthedocs.io/en/stable/>`_ for how to set up, integrate and use the Nuts node.

.. image:: https://circleci.com/gh/nuts-foundation/nuts-node.svg?style=svg
    :target: https://circleci.com/gh/nuts-foundation/nuts-node
    :alt: Build Status

.. image:: https://readthedocs.org/projects/nuts-node/badge/?version=latest
    :target: https://nuts-node.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://api.codeclimate.com/v1/badges/69f77bd34f3ac253cae0/test_coverage
    :target: https://codeclimate.com/github/nuts-foundation/nuts-node/test_coverage
    :alt: Code coverage

.. image:: https://api.codeclimate.com/v1/badges/69f77bd34f3ac253cae0/maintainability
    :target: https://codeclimate.com/github/nuts-foundation/nuts-node/maintainability
    :alt: Maintainability

.. image:: https://github.com/nuts-foundation/nuts-node/actions/workflows/build-images.yaml/badge.svg
    :target: https://github.com/nuts-foundation/nuts-node/actions/workflows/build-images.yaml
    :alt: Build Docker images

.. image:: https://img.shields.io/badge/-Nuts_Community-informational?labelColor=grey&logo=slack
    :target: https://join.slack.com/t/nuts-foundation/shared_invite/zt-19av5q5ur-5fNbZVIFGUw5vDKSy5mqCw
    :alt: Nuts Community on Slack

Development
^^^^^^^^^^^

.. |gover| image:: https://img.shields.io/github/go-mod/go-version/nuts-foundation/nuts-node
    :alt: GitHub go.mod Go version

|gover| or higher is required.

Building
********

Just use ``go build``.

Building for exotic environments
================================

You can build and run the Nuts node on more exotic environments, e.g. Raspberry Pis:

* 32-bit ARMv6 (Raspberry Pi Zero): ``env GOOS=linux GOARCH=arm GOARM=6 go build``

Running tests
*************

Tests can be run by executing

.. code-block:: shell

    go test ./...

Code Generation
***************

Code generation is used for generating mocks, OpenAPI client- and servers, and gRPC services.
Make sure that ``GOPATH/bin`` is available on ``PATH`` and that the dependencies are installed

Install ``protoc``:

  | MacOS: ``brew install protobuf``
  | Linux: ``apt install -y protobuf-compiler``

Install Go tools:

.. code-block:: shell

  make install-tools

Generating code:

To regenerate all code run the ``run-generators`` target from the makefile or use one of the following for a specific group

================ =======================
Group            Command
================ =======================
Mocks            ``make gen-mocks``
OpenApi          ``make gen-api``
Protobuf + gRCP  ``make gen-protobuf``
All              ``make run-generators``
================ =======================

README
======

The readme is auto-generated from a template and uses the documentation to fill in the blanks.

.. code-block:: shell

    make gen-readme

Documentation
=============

The documentation can be build by running the following command from the ``/docs`` directory:

.. code-block:: shell

    make html

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

.. table:: Server Options
    :widths: 20 30 50
    :class: options-table

    =====================================      =================================================================================================================================================================================================================================================================================================================================================================================================      ============================================================================================================================================================================================================================================================================================================================================
    Key                                        Default                                                                                                                                                                                                                                                                                                                                                                                                Description
    =====================================      =================================================================================================================================================================================================================================================================================================================================================================================================      ============================================================================================================================================================================================================================================================================================================================================
    configfile                                 nuts.yaml                                                                                                                                                                                                                                                                                                                                                                                              Nuts config file
    cpuprofile                                                                                                                                                                                                                                                                                                                                                                                                                                        When set, a CPU profile is written to the given path. Ignored when strictmode is set.
    datadir                                    ./data                                                                                                                                                                                                                                                                                                                                                                                                 Directory where the node stores its files.
    internalratelimiter                        true                                                                                                                                                                                                                                                                                                                                                                                                   When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode.
    loggerformat                               text                                                                                                                                                                                                                                                                                                                                                                                                   Log format (text, json)
    strictmode                                 true                                                                                                                                                                                                                                                                                                                                                                                                   When set, insecure settings are forbidden.
    url                                                                                                                                                                                                                                                                                                                                                                                                                                               Public facing URL of the server (required). Must be HTTPS when strictmode is set.
    verbosity                                  info                                                                                                                                                                                                                                                                                                                                                                                                   Log level (trace, debug, info, warn, error)
    httpclient.timeout                         30s                                                                                                                                                                                                                                                                                                                                                                                                    Request time-out for HTTP clients, such as '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.
    tls.certfile                                                                                                                                                                                                                                                                                                                                                                                                                                      PEM file containing the certificate for the server (also used as client certificate). Required in strict mode.
    tls.certheader                                                                                                                                                                                                                                                                                                                                                                                                                                    Name of the HTTP header that will contain the client certificate when TLS is offloaded.
    tls.certkeyfile                                                                                                                                                                                                                                                                                                                                                                                                                                   PEM file containing the private key of the server certificate. Required in strict mode.
    tls.offload                                                                                                                                                                                                                                                                                                                                                                                                                                       Whether to enable TLS offloading for incoming connections. Enable by setting it to 'incoming'. If enabled 'tls.certheader' must be configured as well.
    tls.truststorefile                         truststore.pem                                                                                                                                                                                                                                                                                                                                                                                         PEM file containing the trusted CA certificates for authenticating remote servers. Required in strict mode.
    **Auth**
    auth.accesstokenlifespan                   60                                                                                                                                                                                                                                                                                                                                                                                                     defines how long (in seconds) an access token is valid. Uses default in strict mode.
    auth.clockskew                             5000                                                                                                                                                                                                                                                                                                                                                                                                   allowed JWT Clock skew in milliseconds
    auth.contractvalidators                    [irma,uzi,dummy,employeeid]                                                                                                                                                                                                                                                                                                                                                                            sets the different contract validators to use
    auth.irma.autoupdateschemas                true                                                                                                                                                                                                                                                                                                                                                                                                   set if you want automatically update the IRMA schemas every 60 minutes.
    auth.irma.schememanager                    pbdf                                                                                                                                                                                                                                                                                                                                                                                                   IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'.
    **Crypto**
    crypto.storage                                                                                                                                                                                                                                                                                                                                                                                                                                    Storage to use, 'external' for an external backend (experimental), 'fs' for file system (for development purposes), 'vaultkv' for Vault KV store (recommended, will be replaced by external backend in future).
    crypto.external.address                                                                                                                                                                                                                                                                                                                                                                                                                           Address of the external storage service.
    crypto.external.timeout                    100ms                                                                                                                                                                                                                                                                                                                                                                                                  Time-out when invoking the external storage backend, in Golang time.Duration string format (e.g. 1s).
    crypto.vault.address                                                                                                                                                                                                                                                                                                                                                                                                                              The Vault address. If set it overwrites the VAULT_ADDR env var.
    crypto.vault.pathprefix                    kv                                                                                                                                                                                                                                                                                                                                                                                                     The Vault path prefix.
    crypto.vault.timeout                       5s                                                                                                                                                                                                                                                                                                                                                                                                     Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 1s).
    crypto.vault.token                                                                                                                                                                                                                                                                                                                                                                                                                                The Vault token. If set it overwrites the VAULT_TOKEN env var.
    **Discovery**
    discovery.client.refresh_interval          10m0s                                                                                                                                                                                                                                                                                                                                                                                                  Interval at which the client synchronizes with the Discovery Server; refreshing Verifiable Presentations of local DIDs and loading changes, updating the local copy. It only will actually refresh registrations of local DIDs that about to expire (less than 1/4th of their lifetime left). Specified as Golang duration (e.g. 1m, 1h30m).
    discovery.definitions.directory                                                                                                                                                                                                                                                                                                                                                                                                                   Directory to load Discovery Service Definitions from. If not set, the discovery service will be disabled. If the directory contains JSON files that can't be parsed as service definition, the node will fail to start.
    discovery.server.definition_ids            []                                                                                                                                                                                                                                                                                                                                                                                                     IDs of the Discovery Service Definitions for which to act as server. If an ID does not map to a loaded service definition, the node will fail to start.
    **Events**
    events.nats.hostname                       0.0.0.0                                                                                                                                                                                                                                                                                                                                                                                                Hostname for the NATS server
    events.nats.port                           4222                                                                                                                                                                                                                                                                                                                                                                                                   Port where the NATS server listens on
    events.nats.storagedir                                                                                                                                                                                                                                                                                                                                                                                                                            Directory where file-backed streams are stored in the NATS server
    events.nats.timeout                        30                                                                                                                                                                                                                                                                                                                                                                                                     Timeout for NATS server operations
    **GoldenHammer**
    goldenhammer.enabled                       true                                                                                                                                                                                                                                                                                                                                                                                                   Whether to enable automatically fixing DID documents with the required endpoints.
    goldenhammer.interval                      10m0s                                                                                                                                                                                                                                                                                                                                                                                                  The interval in which to check for DID documents to fix.
    **HTTP**
    http.log                                   metadata                                                                                                                                                                                                                                                                                                                                                                                               What to log about HTTP requests. Options are 'nothing', 'metadata' (log request method, URI, IP and response code), and 'metadata-and-body' (log the request and response body, in addition to the metadata).
    http.internal.address                      localhost:8081                                                                                                                                                                                                                                                                                                                                                                                         Address and port the server will be listening to for internal-facing endpoints.
    http.internal.auth.audience                                                                                                                                                                                                                                                                                                                                                                                                                       Expected audience for JWT tokens (default: hostname)
    http.internal.auth.authorizedkeyspath                                                                                                                                                                                                                                                                                                                                                                                                             Path to an authorized_keys file for trusted JWT signers
    http.internal.auth.type                                                                                                                                                                                                                                                                                                                                                                                                                           Whether to enable authentication for /internal endpoints, specify 'token_v2' for bearer token mode or 'token' for legacy bearer token mode.
    http.public.address                        \:8080                                                                                                                                                                                                                                                                                                                                                                                                  Address and port the server will be listening to for public-facing endpoints.
    **JSONLD**
    jsonld.contexts.localmapping               [https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson,https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson,https://w3id.org/vc/status-list/2021/v1=assets/contexts/w3c-statuslist2021.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson]      This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist.
    jsonld.contexts.remoteallowlist            [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json,https://w3id.org/vc/status-list/2021/v1]                                                                                                                                                                                                                                 In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here.
    **Network**
    network.bootstrapnodes                     []                                                                                                                                                                                                                                                                                                                                                                                                     List of bootstrap nodes ('<host>:<port>') which the node initially connect to.
    network.connectiontimeout                  5000                                                                                                                                                                                                                                                                                                                                                                                                   Timeout before an outbound connection attempt times out (in milliseconds).
    network.enablediscovery                    true                                                                                                                                                                                                                                                                                                                                                                                                   Whether to enable automatic connecting to other nodes.
    network.grpcaddr                           \:5555                                                                                                                                                                                                                                                                                                                                                                                                  Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made).
    network.maxbackoff                         24h0m0s                                                                                                                                                                                                                                                                                                                                                                                                Maximum between outbound connections attempts to unresponsive nodes (in Golang duration format, e.g. '1h', '30m').
    network.nodedid                                                                                                                                                                                                                                                                                                                                                                                                                                   Specifies the DID of the party that operates this node. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.
    network.protocols                          []                                                                                                                                                                                                                                                                                                                                                                                                     Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.
    network.v2.diagnosticsinterval             5000                                                                                                                                                                                                                                                                                                                                                                                                   Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable).
    network.v2.gossipinterval                  5000                                                                                                                                                                                                                                                                                                                                                                                                   Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes.
    **PKI**
    pki.maxupdatefailhours                     4                                                                                                                                                                                                                                                                                                                                                                                                      Maximum number of hours that a denylist update can fail
    pki.softfail                               true                                                                                                                                                                                                                                                                                                                                                                                                   Do not reject certificates if their revocation status cannot be established when softfail is true
    **Storage**
    storage.bbolt.backup.directory                                                                                                                                                                                                                                                                                                                                                                                                                    Target directory for BBolt database backups.
    storage.bbolt.backup.interval              0s                                                                                                                                                                                                                                                                                                                                                                                                     Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed.
    storage.redis.address                                                                                                                                                                                                                                                                                                                                                                                                                             Redis database server address. This can be a simple 'host:port' or a Redis connection URL with scheme, auth and other options.
    storage.redis.database                                                                                                                                                                                                                                                                                                                                                                                                                            Redis database name, which is used as prefix every key. Can be used to have multiple instances use the same Redis instance.
    storage.redis.password                                                                                                                                                                                                                                                                                                                                                                                                                            Redis database password. If set, it overrides the username in the connection URL.
    storage.redis.username                                                                                                                                                                                                                                                                                                                                                                                                                            Redis database username. If set, it overrides the username in the connection URL.
    storage.redis.sentinel.master                                                                                                                                                                                                                                                                                                                                                                                                                     Name of the Redis Sentinel master. Setting this property enables Redis Sentinel.
    storage.redis.sentinel.nodes               []                                                                                                                                                                                                                                                                                                                                                                                                     Addresses of the Redis Sentinels to connect to initially. Setting this property enables Redis Sentinel.
    storage.redis.sentinel.password                                                                                                                                                                                                                                                                                                                                                                                                                   Password for authenticating to Redis Sentinels.
    storage.redis.sentinel.username                                                                                                                                                                                                                                                                                                                                                                                                                   Username for authenticating to Redis Sentinels.
    storage.redis.tls.truststorefile                                                                                                                                                                                                                                                                                                                                                                                                                  PEM file containing the trusted CA certificate(s) for authenticating remote Redis servers. Can only be used when connecting over TLS (use 'rediss://' as scheme in address).
    storage.sql.connection                                                                                                                                                                                                                                                                                                                                                                                                                            Connection string for the SQL database. If not set it, defaults to a SQLite database stored inside the configured data directory. Note: using SQLite is not recommended in production environments. If using SQLite anyways, remember to enable foreign keys ('_foreign_keys=on') and the write-ahead-log ('_journal_mode=WAL').
    **VCR**
    vcr.openid4vci.definitionsdir                                                                                                                                                                                                                                                                                                                                                                                                                     Directory with the additional credential definitions the node could issue (experimental, may change without notice).
    vcr.openid4vci.enabled                     true                                                                                                                                                                                                                                                                                                                                                                                                   Enable issuing and receiving credentials over OpenID4VCI.
    vcr.openid4vci.timeout                     30s                                                                                                                                                                                                                                                                                                                                                                                                    Time-out for OpenID4VCI HTTP client operations.
    **policy**
    policy.address                                                                                                                                                                                                                                                                                                                                                                                                                                    The address of a remote policy server. Mutual exclusive with policy.directory.
    policy.directory                                                                                                                                                                                                                                                                                                                                                                                                                                  Directory to read policy files from. Policy files are JSON files that contain a scope to PresentationDefinition mapping. Mutual exclusive with policy.address.
    =====================================      =================================================================================================================================================================================================================================================================================================================================================================================================      ============================================================================================================================================================================================================================================================================================================================================

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
Therefore is requires TLS to be configured through ``tls.{certfile,certkeyfile,truststore}``.
To verify that authentication is correctly configured on your node, check the ``network.auth_config`` status on the ``/health`` endpoint.
See :ref:`getting started <configure-node>` on how to set this up correctly.

The incorporated `IRMA server <https://irma.app/docs/irma-server/#production-mode>`_ is automatically changed to production mode.
In fact, running in strict mode is the only way to enable IRMA's production mode.
In addition, it requires ``auth.irma.schememanager=pbdf``.

As a general safety precaution ``auth.contractvalidators`` ignores the ``dummy`` option if configured,
requesting an access token from another node on ``/n2n/auth/v1/accesstoken`` does not return any error details,
``auth.accesstokenlifespan`` is always 60 seconds, ``http.default.cors.origin`` does not allow a wildcard (``*``),
json-ld context can only be downloaded from trusted domains configured in ``jsonld.contexts.remoteallowlist``,
and the ``internalratelimiter`` is always on.

Interacting with remote Nuts nodes requires HTTPS: it will refuse to connect to plain HTTP endpoints when in strict mode.

