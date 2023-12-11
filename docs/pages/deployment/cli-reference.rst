.. _nuts-cli-reference:

CLI Command Reference
#####################

There are 2 types of commands: server command and client commands. Server commands (e.g. ``nuts server``) can only be run on the system where the node is (or will be) running, because they require the node's config. Client commands are used to remotely administer a Nuts node and require the node's API address.

Server Commands
***************

The following options apply to the server commands below:


::

      --auth.accesstokenlifespan int                  defines how long (in seconds) an access token is valid. Uses default in strict mode. (default 60)
      --auth.clockskew int                            allowed JWT Clock skew in milliseconds (default 5000)
      --auth.contractvalidators strings               sets the different contract validators to use (default [irma,uzi,dummy,employeeid])
      --auth.http.timeout int                         HTTP timeout (in seconds) used by the Auth API HTTP client (default 30)
      --auth.irma.autoupdateschemas                   set if you want automatically update the IRMA schemas every 60 minutes. (default true)
      --auth.irma.schememanager string                IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'. (default "pbdf")
      --configfile string                             Nuts config file (default "nuts.yaml")
      --cpuprofile string                             When set, a CPU profile is written to the given path. Ignored when strictmode is set.
      --crypto.external.address string                Address of the external storage service.
      --crypto.external.timeout duration              Time-out when invoking the external storage backend, in Golang time.Duration string format (e.g. 1s). (default 100ms)
      --crypto.storage string                         Storage to use, 'external' for an external backend (experimental), 'fs' for file system (for development purposes), 'vaultkv' for Vault KV store (recommended, will be replaced by external backend in future). (default "fs")
      --crypto.vault.address string                   The Vault address. If set it overwrites the VAULT_ADDR env var.
      --crypto.vault.pathprefix string                The Vault path prefix. (default "kv")
      --crypto.vault.timeout duration                 Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 1s). (default 5s)
      --crypto.vault.token string                     The Vault token. If set it overwrites the VAULT_TOKEN env var.
      --datadir string                                Directory where the node stores its files. (default "./data")
      --discovery.definitions.directory string        Directory to load Discovery Service Definitions from. If not set, the discovery service will be disabled. If the directory contains JSON files that can't be parsed as service definition, the node will fail to start.
      --discovery.server.definition_ids strings       IDs of the Discovery Service Definitions for which to act as server. If an ID does not map to a loaded service definition, the node will fail to start.
      --events.nats.hostname string                   Hostname for the NATS server (default "0.0.0.0")
      --events.nats.port int                          Port where the NATS server listens on (default 4222)
      --events.nats.storagedir string                 Directory where file-backed streams are stored in the NATS server
      --events.nats.timeout int                       Timeout for NATS server operations (default 30)
      --goldenhammer.enabled                          Whether to enable automatically fixing DID documents with the required endpoints. (default true)
      --goldenhammer.interval duration                The interval in which to check for DID documents to fix. (default 10m0s)
      --http.default.address string                   Address and port the server will be listening to (default ":1323")
      --http.default.auth.audience string             Expected audience for JWT tokens (default: hostname)
      --http.default.auth.authorizedkeyspath string   Path to an authorized_keys file for trusted JWT signers
      --http.default.auth.type string                 Whether to enable authentication for the default interface, specify 'token_v2' for bearer token mode or 'token' for legacy bearer token mode.
      --http.default.cors.origin strings              When set, enables CORS from the specified origins on the default HTTP interface.
      --http.default.log string                       What to log about HTTP requests. Options are 'nothing', 'metadata' (log request method, URI, IP and response code), and 'metadata-and-body' (log the request and response body, in addition to the metadata). (default "metadata")
      --http.default.tls string                       Whether to enable TLS for the default interface, options are 'disabled', 'server', 'server-client'. Leaving it empty is synonymous to 'disabled',
      --internalratelimiter                           When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode. (default true)
      --jsonld.contexts.localmapping stringToString   This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist. (default [https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson,https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson])
      --jsonld.contexts.remoteallowlist strings       In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here. (default [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json])
      --loggerformat string                           Log format (text, json) (default "text")
      --network.bootstrapnodes strings                List of bootstrap nodes ('<host>:<port>') which the node initially connect to.
      --network.connectiontimeout int                 Timeout before an outbound connection attempt times out (in milliseconds). (default 5000)
      --network.enablediscovery                       Whether to enable automatic connecting to other nodes. (default true)
      --network.enabletls                             Whether to enable TLS for gRPC connections, which can be disabled for demo/development purposes. It is NOT meant for TLS offloading (see 'tls.offload'). Disabling TLS is not allowed in strict-mode. (default true)
      --network.grpcaddr string                       Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made). (default ":5555")
      --network.maxbackoff duration                   Maximum between outbound connections attempts to unresponsive nodes (in Golang duration format, e.g. '1h', '30m'). (default 24h0m0s)
      --network.nodedid string                        Specifies the DID of the organization that operates this node, typically a vendor for EPD software. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.
      --network.protocols ints                        Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.
      --network.v2.diagnosticsinterval int            Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable). (default 5000)
      --network.v2.gossipinterval int                 Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes. (default 5000)
      --pki.maxupdatefailhours int                    Maximum number of hours that a denylist update can fail (default 4)
      --pki.softfail                                  Do not reject certificates if their revocation status cannot be established when softfail is true (default true)
      --storage.bbolt.backup.directory string         Target directory for BBolt database backups.
      --storage.bbolt.backup.interval duration        Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed.
      --storage.redis.address string                  Redis database server address. This can be a simple 'host:port' or a Redis connection URL with scheme, auth and other options.
      --storage.redis.database string                 Redis database name, which is used as prefix every key. Can be used to have multiple instances use the same Redis instance.
      --storage.redis.password string                 Redis database password. If set, it overrides the username in the connection URL.
      --storage.redis.sentinel.master string          Name of the Redis Sentinel master. Setting this property enables Redis Sentinel.
      --storage.redis.sentinel.nodes strings          Addresses of the Redis Sentinels to connect to initially. Setting this property enables Redis Sentinel.
      --storage.redis.sentinel.password string        Password for authenticating to Redis Sentinels.
      --storage.redis.sentinel.username string        Username for authenticating to Redis Sentinels.
      --storage.redis.tls.truststorefile string       PEM file containing the trusted CA certificate(s) for authenticating remote Redis servers. Can only be used when connecting over TLS (use 'rediss://' as scheme in address).
      --storage.redis.username string                 Redis database username. If set, it overrides the username in the connection URL.
      --storage.sql.connection string                 Connection string for the SQL database. If not set it, defaults to a SQLite database stored inside the configured data directory. Note: using SQLite is not recommended in production environments. If using SQLite anyways, remember to enable foreign keys ('_foreign_keys=on') and the write-ahead-log ('_journal_mode=WAL').
      --strictmode                                    When set, insecure settings are forbidden. (default true)
      --tls.certfile string                           PEM file containing the certificate for the server (also used as client certificate).
      --tls.certheader string                         Name of the HTTP header that will contain the client certificate when TLS is offloaded.
      --tls.certkeyfile string                        PEM file containing the private key of the server certificate.
      --tls.offload string                            Whether to enable TLS offloading for incoming connections. Enable by setting it to 'incoming'. If enabled 'tls.certheader' must be configured as well.
      --tls.truststorefile string                     PEM file containing the trusted CA certificates for authenticating remote servers. (default "truststore.pem")
      --url string                                    Public facing URL of the server (required). Must be HTTPS when strictmode is set.
      --vcr.openid4vci.definitionsdir string          Directory with the additional credential definitions the node could issue (experimental, may change without notice).
      --vcr.openid4vci.enabled                        Enable issuing and receiving credentials over OpenID4VCI. (default true)
      --vcr.openid4vci.timeout duration               Time-out for OpenID4VCI HTTP client operations. (default 30s)
      --verbosity string                              Log level (trace, debug, info, warn, error) (default "info")

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


Client Commands
***************


nuts didman svc add
^^^^^^^^^^^^^^^^^^^

Adds a service of the specified type to DID document identified by the given DID. The given service endpoint can either be a string a compound service map in JSON format.

::

  nuts didman svc add [DID] [type] [endpoint] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for add
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts didman svc delete
^^^^^^^^^^^^^^^^^^^^^^

Deletes a service from a DID document.

::

  nuts didman svc delete [DID] [type] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for delete
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts network get
^^^^^^^^^^^^^^^^

Gets a transaction from the network

::

  nuts network get [ref] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for get
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts network list
^^^^^^^^^^^^^^^^^

Lists the transactions on the network

::

  nuts network list [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --end string          exclusive end of lamport clock range
  -h, --help                help for list
      --sort string         sort the results on either time or type (default "time")
      --start string        inclusive start of lamport clock range
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts network payload
^^^^^^^^^^^^^^^^^^^^

Retrieves the payload of a transaction from the network

::

  nuts network payload [ref] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for payload
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts network peers
^^^^^^^^^^^^^^^^^^

Get diagnostic information of the node's peers

::

  nuts network peers [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for peers
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts network reprocess
^^^^^^^^^^^^^^^^^^^^^^

Reprocess all transactions with the give contentType (ex: application/did+json)

::

  nuts network reprocess [contentType] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for reprocess
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts status
^^^^^^^^^^^

Shows the status of the Nuts Node.

::

  nuts status [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for status
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vcr issue
^^^^^^^^^^^^^^

Issues a Verifiable Credential as the given issuer (as DID). The context must be a single JSON-LD context URI (e.g. 'https://nuts.nl/credentials/v1'). The type must be a single VC type (not being VerifiableCredential). The subject must be the credential subject in JSON format. It prints the issued VC if successfully issued.

::

  nuts vcr issue [context] [type] [issuer-did] [subject] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -e, --expiration string   Date in RFC3339 format when the VC expires.
  -h, --help                help for issue
  -p, --publish             Whether to publish the credential to the network. (default true)
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")
  -v, --visibility string   Whether to publish the credential publicly ('public') or privately ('private'). (default "private")

**Example**

::

  nuts vcr issue "https://nuts.nl/credentials/v1" "NutsAuthorizationCredential" "did:nuts:1234" "{'id': 'did:nuts:4321', 'purposeOfUse': 'eOverdracht-sender', 'etc': 'etcetc'}"


nuts vcr list-trusted
^^^^^^^^^^^^^^^^^^^^^

List trusted issuers for given credential type

::

  nuts vcr list-trusted [type] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for list-trusted
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vcr list-untrusted
^^^^^^^^^^^^^^^^^^^^^^^

List untrusted issuers for given credential type

::

  nuts vcr list-untrusted [type] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for list-untrusted
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vcr trust
^^^^^^^^^^^^^^

Trust VCs of a certain credential type when published by the given issuer.

::

  nuts vcr trust [type] [issuer DID] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for trust
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vcr untrust
^^^^^^^^^^^^^^^^

Untrust VCs of a certain credential type when published by the given issuer.

::

  nuts vcr untrust [type] [issuer DID] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for untrust
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vdr add-keyagreement
^^^^^^^^^^^^^^^^^^^^^^^^^

Add a key agreement key to the DID document. It must be a reference to an existing key in the same DID document, for instance created using the 'addvm' command. When successful, it outputs the updated DID document.

::

  nuts vdr add-keyagreement [KID] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for add-keyagreement
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vdr addvm
^^^^^^^^^^^^^^

Add a verification method key to the DID document.

::

  nuts vdr addvm [DID] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for addvm
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vdr conflicted
^^^^^^^^^^^^^^^^^^^

Print conflicted documents and their metadata

::

  nuts vdr conflicted [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --document            Pass 'true' to only print the document (unless other flags are provided as well).
  -h, --help                help for conflicted
      --metadata            Pass 'true' to only print the metadata (unless other flags are provided as well).
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vdr create-did
^^^^^^^^^^^^^^^^^^^

When using the V2 API, a did:web DID will be created. All the other options are ignored for did:web.

::

  nuts vdr create-did [flags]

      --address string         Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --assertionMethod        Pass 'false' to disable assertionMethod capabilities. (default true)
      --authentication         Pass 'true' to enable authentication capabilities.
      --capabilityDelegation   Pass 'true' to enable capabilityDelegation capabilities.
      --capabilityInvocation   Pass 'false' to disable capabilityInvocation capabilities. (default true)
      --controllers strings    Comma-separated list of DIDs that can control the generated DID Document.
  -h, --help                   help for create-did
      --keyAgreement           Pass 'false' to disable keyAgreement capabilities. (default true)
      --selfControl            Pass 'false' to disable DID Document control. (default true)
      --timeout duration       Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string           Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string      File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --v2                     Pass 'true' to use the V2 API and create a did:web DID.
      --verbosity string       Log level (trace, debug, info, warn, error) (default "info")

nuts vdr deactivate
^^^^^^^^^^^^^^^^^^^

Deactivate a DID document based on its DID

::

  nuts vdr deactivate [DID] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for deactivate
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vdr delvm
^^^^^^^^^^^^^^

Deletes a verification method from the DID document.

::

  nuts vdr delvm [DID] [kid] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for delvm
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vdr resolve
^^^^^^^^^^^^^^^^

Resolve a DID document based on its DID

::

  nuts vdr resolve [DID] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --document            Pass 'true' to only print the document (unless other flags are provided as well).
  -h, --help                help for resolve
      --metadata            Pass 'true' to only print the metadata (unless other flags are provided as well).
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")

nuts vdr update
^^^^^^^^^^^^^^^

Update a DID with the given DID document, this replaces the DID document. If no file is given, a pipe is assumed. The hash is needed to prevent concurrent updates.

::

  nuts vdr update [DID] [hash] [file] [flags]

      --address string      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help                help for update
      --timeout duration    Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --token string        Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.
      --token-file string   File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.
      --verbosity string    Log level (trace, debug, info, warn, error) (default "info")
