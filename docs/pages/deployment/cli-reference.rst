.. _nuts-cli-reference:

CLI Command Reference
#####################

There are 2 types of commands: server command and client commands. Server commands (e.g. ``nuts server``) can only be run on the system where the node is (or will be) running, because they require the node's config. Client commands are used to remotely administer a Nuts node and require the node's API address.

Server Commands
***************

The following options apply to the server commands below:


::

      --configfile string                              Nuts config file (default "nuts.yaml")
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
      --discovery.definitions.directory string         Directory to load Discovery Service Definitions from. If not set, the discovery service will be disabled. If the directory contains JSON files that can't be parsed as service definition, the node will fail to start.
      --discovery.server.ids strings                   IDs of the Discovery Service for which to act as server. If an ID does not map to a loaded service definition, the node will fail to start.
      --http.internal.address string                   Address and port the server will be listening to for internal-facing endpoints. (default "localhost:8081")
      --http.internal.auth.audience string             Expected audience for JWT tokens (default: hostname)
      --http.internal.auth.authorizedkeyspath string   Path to an authorized_keys file for trusted JWT signers
      --http.internal.auth.type string                 Whether to enable authentication for /internal endpoints, specify 'token_v2' for bearer token mode or 'token' for legacy bearer token mode.
      --http.log string                                What to log about HTTP requests. Options are 'nothing', 'metadata' (log request method, URI, IP and response code), and 'metadata-and-body' (log the request and response body, in addition to the metadata). (default "metadata")
      --http.public.address string                     Address and port the server will be listening to for public-facing endpoints. (default ":8080")
      --httpclient.timeout duration                    Request time-out for HTTP clients, such as '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 30s)
      --jsonld.contexts.localmapping stringToString    This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist. (default [https://w3id.org/vc/status-list/2021/v1=assets/contexts/w3c-statuslist2021.ldjson,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json=assets/contexts/lds-jws2020-v1.ldjson,https://schema.org=assets/contexts/schema-org-v13.ldjson,https://nuts.nl/credentials/v1=assets/contexts/nuts.ldjson,https://www.w3.org/2018/credentials/v1=assets/contexts/w3c-credentials-v1.ldjson])
      --jsonld.contexts.remoteallowlist strings        In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here. (default [https://schema.org,https://www.w3.org/2018/credentials/v1,https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json,https://w3id.org/vc/status-list/2021/v1])
      --loggerformat string                            Log format (text, json) (default "text")
      --pki.maxupdatefailhours int                     Maximum number of hours that a denylist update can fail (default 4)
      --pki.softfail                                   Do not reject certificates if their revocation status cannot be established when softfail is true (default true)
      --policy.address string                          The address of a remote policy server. Mutual exclusive with policy.directory.
      --policy.directory string                        Directory to read policy files from. Policy files are JSON files that contain a scope to PresentationDefinition mapping. Mutual exclusive with policy.address.
      --storage.sql.connection string                  Connection string for the SQL database. If not set it, defaults to a SQLite database stored inside the configured data directory. Note: using SQLite is not recommended in production environments. If using SQLite anyways, remember to enable foreign keys ('_foreign_keys=on') and the write-ahead-log ('_journal_mode=WAL').
      --strictmode                                     When set, insecure settings are forbidden. (default true)
      --url string                                     Public facing URL of the server (required). Must be HTTPS when strictmode is set.
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


