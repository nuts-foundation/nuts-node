.. _nuts-cli-reference:

CLI Command Reference
#####################

There are 2 types of commands: server command and client commands. Server commands (e.g. ``nuts server``) can only be run on the system where the node is (or will be) running, because they require the node's config. Client commands are used to remotely administer a Nuts node and require the node's API address.

Server Commands
***************

The following options apply to the server commands below:


::

      --auth.accesstokenlifespan int                   defines how long (in seconds) an access token is valid. Uses default in strict mode. (default 60)
      --auth.clockskew int                             allowed JWT Clock skew in milliseconds (default 5000)
      --auth.contractvalidators strings                sets the different contract validators to use (default [irma,dummy,employeeid])
      --auth.irma.autoupdateschemas                    set if you want automatically update the IRMA schemas every 60 minutes. (default true)
      --auth.irma.schememanager string                 IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'. (default "pbdf")
      --configfile string                              Nuts config file (default "./config/nuts.yaml")
      --cpuprofile string                              When set, a CPU profile is written to the given path. Ignored when strictmode is set.
      --crypto.external.address string                 Address of the external storage service.
      --crypto.external.timeout duration               Time-out when invoking the external storage backend, in Golang time.Duration string format (e.g. 1s). (default 100ms)
      --crypto.storage string                          Storage to use, 'external' for an external backend (experimental), 'fs' for file system (for development purposes), 'vaultkv' for Vault KV store (recommended, will be replaced by external backend in future).
      --crypto.vault.address string                    The Vault address. If set it overwrites the VAULT_ADDR env var.
      --crypto.vault.pathprefix string                 The Vault path prefix. (default "kv")
      --crypto.vault.timeout duration                  Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 1s). (default 5s)
      --crypto.vault.token string                      The Vault token. If set it overwrites the VAULT_TOKEN env var.
      --datadir string                                 Directory where the node stores its files. (default "./data")
      --discovery.client.refresh_interval duration     Interval at which the client synchronizes with the Discovery Server; refreshing Verifiable Presentations of local DIDs and loading changes, updating the local copy. It only will actually refresh registrations of local DIDs that about to expire (less than 1/4th of their lifetime left). Specified as Golang duration (e.g. 1m, 1h30m). (default 10m0s)
      --discovery.definitions.directory string         Directory to load Discovery Service Definitions from. If not set, the discovery service will be disabled. If the directory contains JSON files that can't be parsed as service definition, the node will fail to start. (default "./config/discovery")
      --discovery.server.ids strings                   IDs of the Discovery Service for which to act as server. If an ID does not map to a loaded service definition, the node will fail to start.
      --events.nats.hostname string                    Hostname for the NATS server (default "0.0.0.0")
      --events.nats.port int                           Port where the NATS server listens on (default 4222)
      --events.nats.storagedir string                  Directory where file-backed streams are stored in the NATS server
      --events.nats.timeout int                        Timeout for NATS server operations (default 30)
      --goldenhammer.enabled                           Whether to enable automatically fixing DID documents with the required endpoints. (default true)
      --goldenhammer.interval duration                 The interval in which to check for DID documents to fix. (default 10m0s)
      --http.internal.address string                   Address and port the server will be listening to for internal-facing endpoints. (default "127.0.0.1:8081")
      --http.internal.auth.audience string             Expected audience for JWT tokens (default: hostname)
      --http.internal.auth.authorizedkeyspath string   Path to an authorized_keys file for trusted JWT signers
      --http.internal.auth.type string                 Whether to enable authentication for /internal endpoints, specify 'token_v2' for bearer token mode or 'token' for legacy bearer token mode.
      --http.log string                                What to log about HTTP requests. Options are 'nothing', 'metadata' (log request method, URI, IP and response code), and 'metadata-and-body' (log the request and response body, in addition to the metadata). (default "metadata")
      --http.public.address string                     Address and port the server will be listening to for public-facing endpoints. (default ":8080")
      --httpclient.timeout duration                    Request time-out for HTTP clients, such as '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 30s)
      --internalratelimiter                            When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode. (default true)
      --jsonld.contexts.localmapping stringToString    This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist. (default [https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson,https://w3id.org/vc/status-list/2021/v1=assets/contexts/w3c-statuslist2021.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson,https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson])
      --jsonld.contexts.remoteallowlist strings        In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here. (default [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json,https://w3id.org/vc/status-list/2021/v1])
      --loggerformat string                            Log format (text, json) (default "text")
      --network.bootstrapnodes strings                 List of bootstrap nodes ('<host>:<port>') which the node initially connect to.
      --network.connectiontimeout int                  Timeout before an outbound connection attempt times out (in milliseconds). (default 5000)
      --network.enablediscovery                        Whether to enable automatic connecting to other nodes. (default true)
      --network.grpcaddr string                        Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made). (default ":5555")
      --network.maxbackoff duration                    Maximum between outbound connections attempts to unresponsive nodes (in Golang duration format, e.g. '1h', '30m'). (default 24h0m0s)
      --network.nodedid string                         Specifies the DID of the party that operates this node. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.
      --network.protocols ints                         Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.
      --network.v2.diagnosticsinterval int             Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable). (default 5000)
      --network.v2.gossipinterval int                  Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes. (default 5000)
      --pki.maxupdatefailhours int                     Maximum number of hours that a denylist update can fail (default 4)
      --pki.softfail                                   Do not reject certificates if their revocation status cannot be established when softfail is true (default true)
      --policy.address string                          The address of a remote policy server. Mutual exclusive with policy.directory.
      --policy.directory string                        Directory to read policy files from. Policy files are JSON files that contain a scope to PresentationDefinition mapping. Mutual exclusive with policy.address. (default "./config/policy")
      --storage.bbolt.backup.directory string          Target directory for BBolt database backups.
      --storage.bbolt.backup.interval duration         Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed.
      --storage.redis.address string                   Redis database server address. This can be a simple 'host:port' or a Redis connection URL with scheme, auth and other options.
      --storage.redis.database string                  Redis database name, which is used as prefix every key. Can be used to have multiple instances use the same Redis instance.
      --storage.redis.password string                  Redis database password. If set, it overrides the username in the connection URL.
      --storage.redis.sentinel.master string           Name of the Redis Sentinel master. Setting this property enables Redis Sentinel.
      --storage.redis.sentinel.nodes strings           Addresses of the Redis Sentinels to connect to initially. Setting this property enables Redis Sentinel.
      --storage.redis.sentinel.password string         Password for authenticating to Redis Sentinels.
      --storage.redis.sentinel.username string         Username for authenticating to Redis Sentinels.
      --storage.redis.tls.truststorefile string        PEM file containing the trusted CA certificate(s) for authenticating remote Redis servers. Can only be used when connecting over TLS (use 'rediss://' as scheme in address).
      --storage.redis.username string                  Redis database username. If set, it overrides the username in the connection URL.
      --storage.sql.connection string                  Connection string for the SQL database. If not set it, defaults to a SQLite database stored inside the configured data directory. Note: using SQLite is not recommended in production environments. If using SQLite anyways, remember to enable foreign keys ('_foreign_keys=on') and the write-ahead-log ('_journal_mode=WAL').
      --strictmode                                     When set, insecure settings are forbidden. (default true)
      --tls.certfile string                            PEM file containing the certificate for the gRPC server (also used as client certificate). Required in strict mode.
      --tls.certheader string                          Name of the HTTP header that will contain the client certificate when TLS is offloaded for gRPC.
      --tls.certkeyfile string                         PEM file containing the private key of the gRPC server certificate. Required in strict mode.
      --tls.offload string                             Whether to enable TLS offloading for incoming gRPC connections. Enable by setting it to 'incoming'. If enabled 'tls.certheader' must be configured as well.
      --tls.truststorefile string                      PEM file containing the trusted CA certificates for authenticating remote gRPC servers. Required in strict mode. (default "./config/ssl/truststore.pem")
      --url string                                     Public facing URL of the server (required). Must be HTTPS when strictmode is set.
      --vcr.openid4vci.definitionsdir string           Directory with the additional credential definitions the node could issue (experimental, may change without notice).
      --vcr.openid4vci.enabled                         Enable issuing and receiving credentials over OpenID4VCI. (default true)
      --vcr.openid4vci.timeout duration                Time-out for OpenID4VCI HTTP client operations. (default 30s)
      --verbosity string                               Log level (trace, debug, info, warn, error) (default "info")

nuts config
^^^^^^^^^^^

Prints the current config

::

  nuts config [flags]


nuts crypto fs2external
^^^^^^^^^^^^^^^^^^^^^^^

Imports private keys from filesystem based storage into the secret store server. The given directory must contain the private key files. The Nuts node must be configured to use storage-api as crypto storage. Can only be run on the local Nuts node, from the directory where nuts.yaml resides.

::

  nuts crypto fs2external [directory] [flags]


nuts crypto fs2vault
^^^^^^^^^^^^^^^^^^^^

Imports private keys from filesystem based storage into Vault. The given directory must contain the private key files.The Nuts node must be configured to use Vault as crypto storage. Can only be run on the local Nuts node, from the directory where nuts.yaml resides.

::

  nuts crypto fs2vault [directory] [flags]


nuts http gen-token
^^^^^^^^^^^^^^^^^^^

Generates an access token for administrative operations.

::

  nuts http gen-token [user name] [days valid] [flags]


nuts server
^^^^^^^^^^^

Starts the Nuts server

::

  nuts server [flags]


