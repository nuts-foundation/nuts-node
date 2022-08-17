.. _nuts-cli-reference:

CLI Command Reference
*********************


nuts
^^^^

Nuts executable which can be used to run the Nuts server or administer the remote Nuts server.

::

  nuts [flags]

  -h, --help   help for nuts

nuts config
^^^^^^^^^^^

Prints the current config

::

  nuts config [flags]

      --auth.clockskew int                            Allowed JWT Clock skew in milliseconds (default 5000)
      --auth.contractvalidators strings               sets the different contract validators to use (default [irma,uzi,dummy])
      --auth.http.timeout int                         HTTP timeout (in seconds) used by the Auth API HTTP client (default 30)
      --auth.irma.autoupdateschemas                   set if you want automatically update the IRMA schemas every 60 minutes. (default true)
      --auth.irma.schememanager string                IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'. (default "pbdf")
      --auth.publicurl string                         public URL which can be reached by a users IRMA client, this should include the scheme and domain: https://example.com. Additional paths should only be added if some sort of url-rewriting is done in a reverse-proxy.
      --configfile string                             Nuts config file (default "nuts.yaml")
      --cpuprofile string                             When set, a CPU profile is written to the given path. Ignored when strictmode is set.
      --crypto.storage string                         Storage to use, 'fs' for file system, vaultkv for Vault KV store, default: fs. (default "fs")
      --crypto.vault.address string                   The Vault address. If set it overwrites the VAULT_ADDR env var.
      --crypto.vault.pathprefix string                The Vault path prefix. default: kv. (default "kv")
      --crypto.vault.timeout duration                 Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 5s). (default 5s)
      --crypto.vault.token string                     The Vault token. If set it overwrites the VAULT_TOKEN env var.
      --datadir string                                Directory where the node stores its files. (default "./data")
      --events.nats.hostname string                   Hostname for the NATS server (default "localhost")
      --events.nats.port int                          Port where the NATS server listens on (default 4222)
      --events.nats.storagedir string                 Directory where file-backed streams are stored in the NATS server
      --events.nats.timeout int                       Timeout for NATS server operations (default 30)
  -h, --help                                          help for config
      --http.default.address string                   Address and port the server will be listening to (default ":1323")
      --http.default.cors.origin strings              When set, enables CORS from the specified origins for the on default HTTP interface.
      --http.default.tls string                       Whether to enable TLS for the default interface (options are 'disabled', 'server-cert', 'server-and-client-cert'). (default "disabled")
      --internalratelimiter                           When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode. (default true)
      --jsonld.contexts.localmapping stringToString   This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist. (default [https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson,https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson])
      --jsonld.contexts.remoteallowlist strings       In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here. (default [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json])
      --loggerformat string                           Log format (text, json) (default "text")
      --network.bootstrapnodes strings                List of bootstrap nodes ('<host>:<port>') which the node initially connect to.
      --network.certfile string                       Deprecated: use 'tls.certfile'. PEM file containing the server certificate for the gRPC server. Required when 'network.enabletls' is 'true'.
      --network.certkeyfile string                    Deprecated: use 'tls.certkeyfile'. PEM file containing the private key of the server certificate. Required when 'network.enabletls' is 'true'.
      --network.connectiontimeout int                 Timeout before an outbound connection attempt times out (in milliseconds). (default 5000)
      --network.disablenodeauthentication             Disable node DID authentication using client certificate, causing all node DIDs to be accepted. Unsafe option, only intended for workshops/demo purposes so it's not allowed in strict-mode. Automatically enabled when TLS is disabled.
      --network.enablediscovery                       Whether to enable automatic connecting to other nodes. (default true)
      --network.enabletls                             Whether to enable TLS for gRPC connections, which can be disabled for demo/development purposes. It is NOT meant for TLS offloading (see 'tls.offload'). Disabling TLS is not allowed in strict-mode. (default true)
      --network.grpcaddr string                       Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made). (default ":5555")
      --network.maxbackoff duration                   Maximum between outbound connections attempts to unresponsive nodes (in Golang duration format, e.g. '1h', '30m'). (default 24h0m0s)
      --network.nodedid string                        Specifies the DID of the organization that operates this node, typically a vendor for EPD software. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.
      --network.protocols ints                        Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.
      --network.truststorefile string                 Deprecated: use 'tls.truststorefile'. PEM file containing the trusted CA certificates for authenticating remote gRPC servers.
      --network.v2.diagnosticsinterval int            Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable). (default 5000)
      --network.v2.gossipinterval int                 Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes. (default 5000)
      --storage.bbolt.backup.directory string         Target directory for BBolt database backups.
      --storage.bbolt.backup.interval duration        Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed.
      --storage.redis.address string                  Redis database server address. This can be a simple 'host:port' or a Redis connection URL with scheme, auth and other options.
      --storage.redis.database string                 Redis database name, which is used as prefix every key. Can be used to have multiple instances use the same Redis instance.
      --storage.redis.password string                 Redis database password. If set, it overrides the username in the connection URL.
      --storage.redis.username string                 Redis database username. If set, it overrides the username in the connection URL.
      --strictmode                                    When set, insecure settings are forbidden.
      --tls.certfile string                           PEM file containing the certificate for the server (also used as client certificate).
      --tls.certheader string                         Name of the HTTP header that will contain the client certificate when TLS is offloaded.
      --tls.certkeyfile string                        PEM file containing the private key of the server certificate.
      --tls.offload string                            Whether to enable TLS offloading for incoming connections. If enabled 'tls.certheader' must be configured as well.
      --tls.truststorefile string                     PEM file containing the trusted CA certificates for authenticating remote servers. (default "truststore.pem")
      --verbosity string                              Log level (trace, debug, info, warn, error) (default "info")

nuts crypto fs2vault
^^^^^^^^^^^^^^^^^^^^

Imports private keys from filesystem based storage into Vault. The given directory must contain the private key files.The Nuts node must be configured to use Vault as crypto storage. Can only be run on the local Nuts node, from the directory where nuts.yaml resides.

::

  nuts crypto fs2vault [directory] [flags]

      --auth.clockskew int                            Allowed JWT Clock skew in milliseconds (default 5000)
      --auth.contractvalidators strings               sets the different contract validators to use (default [irma,uzi,dummy])
      --auth.http.timeout int                         HTTP timeout (in seconds) used by the Auth API HTTP client (default 30)
      --auth.irma.autoupdateschemas                   set if you want automatically update the IRMA schemas every 60 minutes. (default true)
      --auth.irma.schememanager string                IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'. (default "pbdf")
      --auth.publicurl string                         public URL which can be reached by a users IRMA client, this should include the scheme and domain: https://example.com. Additional paths should only be added if some sort of url-rewriting is done in a reverse-proxy.
      --configfile string                             Nuts config file (default "nuts.yaml")
      --cpuprofile string                             When set, a CPU profile is written to the given path. Ignored when strictmode is set.
      --crypto.storage string                         Storage to use, 'fs' for file system, vaultkv for Vault KV store, default: fs. (default "fs")
      --crypto.vault.address string                   The Vault address. If set it overwrites the VAULT_ADDR env var.
      --crypto.vault.pathprefix string                The Vault path prefix. default: kv. (default "kv")
      --crypto.vault.timeout duration                 Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 5s). (default 5s)
      --crypto.vault.token string                     The Vault token. If set it overwrites the VAULT_TOKEN env var.
      --datadir string                                Directory where the node stores its files. (default "./data")
      --events.nats.hostname string                   Hostname for the NATS server (default "localhost")
      --events.nats.port int                          Port where the NATS server listens on (default 4222)
      --events.nats.storagedir string                 Directory where file-backed streams are stored in the NATS server
      --events.nats.timeout int                       Timeout for NATS server operations (default 30)
  -h, --help                                          help for fs2vault
      --http.default.address string                   Address and port the server will be listening to (default ":1323")
      --http.default.cors.origin strings              When set, enables CORS from the specified origins for the on default HTTP interface.
      --http.default.tls string                       Whether to enable TLS for the default interface (options are 'disabled', 'server-cert', 'server-and-client-cert'). (default "disabled")
      --internalratelimiter                           When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode. (default true)
      --jsonld.contexts.localmapping stringToString   This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist. (default [https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson,https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson])
      --jsonld.contexts.remoteallowlist strings       In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here. (default [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json])
      --loggerformat string                           Log format (text, json) (default "text")
      --network.bootstrapnodes strings                List of bootstrap nodes ('<host>:<port>') which the node initially connect to.
      --network.certfile string                       Deprecated: use 'tls.certfile'. PEM file containing the server certificate for the gRPC server. Required when 'network.enabletls' is 'true'.
      --network.certkeyfile string                    Deprecated: use 'tls.certkeyfile'. PEM file containing the private key of the server certificate. Required when 'network.enabletls' is 'true'.
      --network.connectiontimeout int                 Timeout before an outbound connection attempt times out (in milliseconds). (default 5000)
      --network.disablenodeauthentication             Disable node DID authentication using client certificate, causing all node DIDs to be accepted. Unsafe option, only intended for workshops/demo purposes so it's not allowed in strict-mode. Automatically enabled when TLS is disabled.
      --network.enablediscovery                       Whether to enable automatic connecting to other nodes. (default true)
      --network.enabletls                             Whether to enable TLS for gRPC connections, which can be disabled for demo/development purposes. It is NOT meant for TLS offloading (see 'tls.offload'). Disabling TLS is not allowed in strict-mode. (default true)
      --network.grpcaddr string                       Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made). (default ":5555")
      --network.maxbackoff duration                   Maximum between outbound connections attempts to unresponsive nodes (in Golang duration format, e.g. '1h', '30m'). (default 24h0m0s)
      --network.nodedid string                        Specifies the DID of the organization that operates this node, typically a vendor for EPD software. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.
      --network.protocols ints                        Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.
      --network.truststorefile string                 Deprecated: use 'tls.truststorefile'. PEM file containing the trusted CA certificates for authenticating remote gRPC servers.
      --network.v2.diagnosticsinterval int            Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable). (default 5000)
      --network.v2.gossipinterval int                 Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes. (default 5000)
      --storage.bbolt.backup.directory string         Target directory for BBolt database backups.
      --storage.bbolt.backup.interval duration        Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed.
      --storage.redis.address string                  Redis database server address. This can be a simple 'host:port' or a Redis connection URL with scheme, auth and other options.
      --storage.redis.database string                 Redis database name, which is used as prefix every key. Can be used to have multiple instances use the same Redis instance.
      --storage.redis.password string                 Redis database password. If set, it overrides the username in the connection URL.
      --storage.redis.username string                 Redis database username. If set, it overrides the username in the connection URL.
      --strictmode                                    When set, insecure settings are forbidden.
      --tls.certfile string                           PEM file containing the certificate for the server (also used as client certificate).
      --tls.certheader string                         Name of the HTTP header that will contain the client certificate when TLS is offloaded.
      --tls.certkeyfile string                        PEM file containing the private key of the server certificate.
      --tls.offload string                            Whether to enable TLS offloading for incoming connections. If enabled 'tls.certheader' must be configured as well.
      --tls.truststorefile string                     PEM file containing the trusted CA certificates for authenticating remote servers. (default "truststore.pem")
      --verbosity string                              Log level (trace, debug, info, warn, error) (default "info")

nuts didman svc add
^^^^^^^^^^^^^^^^^^^

Adds a service of the specified type to DID document identified by the given DID. The given service endpoint can either be a string a compound service map in JSON format.

::

  nuts didman svc add [DID] [type] [endpoint] [flags]

  -h, --help   help for add
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts didman svc delete
^^^^^^^^^^^^^^^^^^^^^^

Deletes a service from a DID document.

::

  nuts didman svc delete [DID] [type] [flags]

  -h, --help   help for delete
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts network get
^^^^^^^^^^^^^^^^

Gets a transaction from the network

::

  nuts network get [ref] [flags]

  -h, --help   help for get
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts network list
^^^^^^^^^^^^^^^^^

Lists the transactions on the network

::

  nuts network list [flags]

  -h, --help          help for list
      --sort string   sort the results on either time or type (default "time")
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts network payload
^^^^^^^^^^^^^^^^^^^^

Retrieves the payload of a transaction from the network

::

  nuts network payload [ref] [flags]

  -h, --help   help for payload
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts network peers
^^^^^^^^^^^^^^^^^^

Get diagnostic information of the node's peers

::

  nuts network peers [flags]

  -h, --help   help for peers
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts network reprocess
^^^^^^^^^^^^^^^^^^^^^^

Reprocess all transactions with the give contentType (ex: application/did+json)

::

  nuts network reprocess [contentType] [flags]

  -h, --help   help for reprocess
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts server
^^^^^^^^^^^

Starts the Nuts server

::

  nuts server [flags]

      --auth.clockskew int                            Allowed JWT Clock skew in milliseconds (default 5000)
      --auth.contractvalidators strings               sets the different contract validators to use (default [irma,uzi,dummy])
      --auth.http.timeout int                         HTTP timeout (in seconds) used by the Auth API HTTP client (default 30)
      --auth.irma.autoupdateschemas                   set if you want automatically update the IRMA schemas every 60 minutes. (default true)
      --auth.irma.schememanager string                IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'. (default "pbdf")
      --auth.publicurl string                         public URL which can be reached by a users IRMA client, this should include the scheme and domain: https://example.com. Additional paths should only be added if some sort of url-rewriting is done in a reverse-proxy.
      --configfile string                             Nuts config file (default "nuts.yaml")
      --cpuprofile string                             When set, a CPU profile is written to the given path. Ignored when strictmode is set.
      --crypto.storage string                         Storage to use, 'fs' for file system, vaultkv for Vault KV store, default: fs. (default "fs")
      --crypto.vault.address string                   The Vault address. If set it overwrites the VAULT_ADDR env var.
      --crypto.vault.pathprefix string                The Vault path prefix. default: kv. (default "kv")
      --crypto.vault.timeout duration                 Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 5s). (default 5s)
      --crypto.vault.token string                     The Vault token. If set it overwrites the VAULT_TOKEN env var.
      --datadir string                                Directory where the node stores its files. (default "./data")
      --events.nats.hostname string                   Hostname for the NATS server (default "localhost")
      --events.nats.port int                          Port where the NATS server listens on (default 4222)
      --events.nats.storagedir string                 Directory where file-backed streams are stored in the NATS server
      --events.nats.timeout int                       Timeout for NATS server operations (default 30)
  -h, --help                                          help for server
      --http.default.address string                   Address and port the server will be listening to (default ":1323")
      --http.default.cors.origin strings              When set, enables CORS from the specified origins for the on default HTTP interface.
      --http.default.tls string                       Whether to enable TLS for the default interface (options are 'disabled', 'server-cert', 'server-and-client-cert'). (default "disabled")
      --internalratelimiter                           When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode. (default true)
      --jsonld.contexts.localmapping stringToString   This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist. (default [https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson,https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson])
      --jsonld.contexts.remoteallowlist strings       In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here. (default [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json])
      --loggerformat string                           Log format (text, json) (default "text")
      --network.bootstrapnodes strings                List of bootstrap nodes ('<host>:<port>') which the node initially connect to.
      --network.certfile string                       Deprecated: use 'tls.certfile'. PEM file containing the server certificate for the gRPC server. Required when 'network.enabletls' is 'true'.
      --network.certkeyfile string                    Deprecated: use 'tls.certkeyfile'. PEM file containing the private key of the server certificate. Required when 'network.enabletls' is 'true'.
      --network.connectiontimeout int                 Timeout before an outbound connection attempt times out (in milliseconds). (default 5000)
      --network.disablenodeauthentication             Disable node DID authentication using client certificate, causing all node DIDs to be accepted. Unsafe option, only intended for workshops/demo purposes so it's not allowed in strict-mode. Automatically enabled when TLS is disabled.
      --network.enablediscovery                       Whether to enable automatic connecting to other nodes. (default true)
      --network.enabletls                             Whether to enable TLS for gRPC connections, which can be disabled for demo/development purposes. It is NOT meant for TLS offloading (see 'tls.offload'). Disabling TLS is not allowed in strict-mode. (default true)
      --network.grpcaddr string                       Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made). (default ":5555")
      --network.maxbackoff duration                   Maximum between outbound connections attempts to unresponsive nodes (in Golang duration format, e.g. '1h', '30m'). (default 24h0m0s)
      --network.nodedid string                        Specifies the DID of the organization that operates this node, typically a vendor for EPD software. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.
      --network.protocols ints                        Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.
      --network.truststorefile string                 Deprecated: use 'tls.truststorefile'. PEM file containing the trusted CA certificates for authenticating remote gRPC servers.
      --network.v2.diagnosticsinterval int            Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable). (default 5000)
      --network.v2.gossipinterval int                 Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes. (default 5000)
      --storage.bbolt.backup.directory string         Target directory for BBolt database backups.
      --storage.bbolt.backup.interval duration        Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed.
      --storage.redis.address string                  Redis database server address. This can be a simple 'host:port' or a Redis connection URL with scheme, auth and other options.
      --storage.redis.database string                 Redis database name, which is used as prefix every key. Can be used to have multiple instances use the same Redis instance.
      --storage.redis.password string                 Redis database password. If set, it overrides the username in the connection URL.
      --storage.redis.username string                 Redis database username. If set, it overrides the username in the connection URL.
      --strictmode                                    When set, insecure settings are forbidden.
      --tls.certfile string                           PEM file containing the certificate for the server (also used as client certificate).
      --tls.certheader string                         Name of the HTTP header that will contain the client certificate when TLS is offloaded.
      --tls.certkeyfile string                        PEM file containing the private key of the server certificate.
      --tls.offload string                            Whether to enable TLS offloading for incoming connections. If enabled 'tls.certheader' must be configured as well.
      --tls.truststorefile string                     PEM file containing the trusted CA certificates for authenticating remote servers. (default "truststore.pem")
      --verbosity string                              Log level (trace, debug, info, warn, error) (default "info")

nuts status
^^^^^^^^^^^

Shows the status of the Nuts Node.

::

  nuts status [flags]

      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help               help for status
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vcr list-trusted
^^^^^^^^^^^^^^^^^^^^^

List trusted issuers for given credential type

::

  nuts vcr list-trusted [type] [flags]

  -h, --help   help for list-trusted
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vcr list-untrusted
^^^^^^^^^^^^^^^^^^^^^^^

List untrusted issuers for given credential type

::

  nuts vcr list-untrusted [type] [flags]

  -h, --help   help for list-untrusted
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vcr trust
^^^^^^^^^^^^^^

Trust VCs of a certain credential type when published by the given issuer.

::

  nuts vcr trust [type] [issuer DID] [flags]

  -h, --help   help for trust
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vcr untrust
^^^^^^^^^^^^^^^^

Untrust VCs of a certain credential type when published by the given issuer.

::

  nuts vcr untrust [type] [issuer DID] [flags]

  -h, --help   help for untrust
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vdr add-keyagreement
^^^^^^^^^^^^^^^^^^^^^^^^^

Add a key agreement key to the DID document. It must be a reference to an existing key in the same DID document, for instance created using the 'addvm' command. When successful, it outputs the updated DID document.

::

  nuts vdr add-keyagreement [KID] [flags]

  -h, --help   help for add-keyagreement
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vdr addvm
^^^^^^^^^^^^^^

Add a verification method key to the DID document.

::

  nuts vdr addvm [DID] [flags]

  -h, --help   help for addvm
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vdr conflicted
^^^^^^^^^^^^^^^^^^^

Print conflicted documents and their metadata

::

  nuts vdr conflicted [flags]

      --document   Pass 'true' to only print the document (unless other flags are provided as well).
  -h, --help       help for conflicted
      --metadata   Pass 'true' to only print the metadata (unless other flags are provided as well).
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vdr create-did
^^^^^^^^^^^^^^^^^^^

Registers a new DID

::

  nuts vdr create-did [flags]

      --assertionMethod        Pass 'false' to disable assertionMethod capabilities. (default true)
      --authentication         Pass 'true' to enable authentication capabilities.
      --capabilityDelegation   Pass 'true' to enable capabilityDelegation capabilities.
      --capabilityInvocation   Pass 'false' to disable capabilityInvocation capabilities. (default true)
      --controllers strings    Comma-separated list of DIDs that can control the generated DID Document.
  -h, --help                   help for create-did
      --keyAgreement           Pass 'true' to enable keyAgreement capabilities.
      --selfControl            Pass 'false' to disable DID Document control. (default true)
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vdr deactivate
^^^^^^^^^^^^^^^^^^^

Deactivate a DID document based on its DID

::

  nuts vdr deactivate [DID] [flags]

  -h, --help   help for deactivate
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vdr delvm
^^^^^^^^^^^^^^

Deletes a verification method from the DID document.

::

  nuts vdr delvm [DID] [kid] [flags]

  -h, --help   help for delvm
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vdr resolve
^^^^^^^^^^^^^^^^

Resolve a DID document based on its DID

::

  nuts vdr resolve [DID] [flags]

      --document   Pass 'true' to only print the document (unless other flags are provided as well).
  -h, --help       help for resolve
      --metadata   Pass 'true' to only print the metadata (unless other flags are provided as well).
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")

nuts vdr update
^^^^^^^^^^^^^^^

Update a DID with the given DID document, this replaces the DID document. If no file is given, a pipe is assumed. The hash is needed to prevent concurrent updates.

::

  nuts vdr update [DID] [hash] [file] [flags]

  -h, --help   help for update
      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")
