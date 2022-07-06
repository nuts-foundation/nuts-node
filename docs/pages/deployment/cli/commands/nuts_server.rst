.. _nuts_server:

nuts server
-----------

Starts the Nuts server

Synopsis
~~~~~~~~


Starts the Nuts server

::

  nuts server [flags]

Options
~~~~~~~

::

      --auth.clockskew int                                Allowed JWT Clock skew in milliseconds (default 5000)
      --auth.contractvalidators strings                   sets the different contract validators to use (default [irma,uzi,dummy])
      --auth.http.timeout int                             HTTP timeout (in seconds) used by the Auth API HTTP client (default 30)
      --auth.irma.autoupdateschemas                       set if you want automatically update the IRMA schemas every 60 minutes. (default true)
      --auth.irma.schememanager string                    IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'. (default "pbdf")
      --auth.publicurl string                             public URL which can be reached by a users IRMA client, this should include the scheme and domain: https://example.com. Additional paths should only be added if some sort of url-rewriting is done in a reverse-proxy.
      --configfile string                                 Nuts config file (default "nuts.yaml")
      --crypto.storage string                             Storage to use, 'fs' for file system, vaultkv for Vault KV store, default: fs. (default "fs")
      --crypto.vault.address string                       The Vault address. If set it overwrites the VAULT_ADDR env var.
      --crypto.vault.pathprefix string                    The Vault path prefix. default: kv. (default "kv")
      --crypto.vault.token string                         The Vault token. If set it overwrites the VAULT_TOKEN env var.
      --datadir string                                    Directory where the node stores its files. (default "./data")
      --events.nats.hostname string                       Hostname for the NATS server (default "localhost")
      --events.nats.port int                              Port where the NATS server listens on (default 4222)
      --events.nats.storagedir string                     Directory where file-backed streams are stored in the NATS server
      --events.nats.timeout int                           Timeout for NATS server operations (default 30)
  -h, --help                                              help for server
      --http.default.address string                       Address and port the server will be listening to (default ":1323")
      --http.default.cors.origin strings                  When set, enables CORS from the specified origins for the on default HTTP interface.
      --jsonld.contexts.localmapping stringToString       This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist. (default [https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson,https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson])
      --jsonld.contexts.remoteallowlist strings           In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here. (default [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json])
      --loggerformat string                               Log format (text, json) (default "text")
      --network.bootstrapnodes <host>:<port>              List of bootstrap nodes (<host>:<port>) which the node initially connect to.
      --network.certfile enableTLS                        PEM file containing the server certificate for the gRPC server. Required when enableTLS is `true`.
      --network.certkeyfile network.enabletls             PEM file containing the private key of the server certificate. Required when network.enabletls is `true`.
      --network.connectiontimeout int                     Timeout before an outbound connection attempt times out (in milliseconds). (default 5000)
      --network.disablenodeauthentication                 Disable node DID authentication using client certificate, causing all node DIDs to be accepted. Unsafe option, only intended for workshops/demo purposes. Not allowed in strict-mode.
      --network.enablediscovery                           Whether to enable automatic connecting to other nodes. (default true)
      --network.enabletls certfile                        Whether to enable TLS for incoming and outgoing gRPC connections. When certfile or `certkeyfile` is specified it defaults to `true`, otherwise `false`. (default true)
      --network.grpcaddr string                           Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made). (default ":5555")
      --network.nodedid string                            Specifies the DID of the organization that operates this node, typically a vendor for EPD software. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.
      --network.protocols ints                            Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.
      --network.truststorefile string                     PEM file containing the trusted CA certificates for authenticating remote gRPC servers.
      --network.v2.diagnosticsinterval int                Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable). (default 5000)
      --network.v2.gossipinterval int                     Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes. (default 5000)
      --storage.databases.bbolt.backup.directory string   Target directory for BBolt database backups.
      --storage.databases.bbolt.backup.interval string    Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed. (default "0")
      --strictmode                                        When set, insecure settings are forbidden.
      --vcr.overrideissueallpublic                        Overrides the "Public" property of a credential when issuing credentials: if set to true, all issued credentials are published as public credentials, regardless of whether they're actually marked as public. (default true)
      --verbosity string                                  Log level (trace, debug, info, warn, error) (default "info")

SEE ALSO
~~~~~~~~

* :ref:`nuts <nuts>` 	 - Nuts executable which can be used to run the Nuts server or administer the remote Nuts server.

*Auto generated by spf13/cobra on 6-Jul-2022*
