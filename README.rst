nuts-node
#########

Distributed registry for storing and querying health care providers their vendors and technical endpoints.

.. image:: https://circleci.com/gh/nuts-foundation/nuts-node.svg?style=svg
    :target: https://circleci.com/gh/nuts-foundation/nuts-node
    :alt: Build Status

.. image:: https://readthedocs.org/projects/nuts-node/badge/?version=latest
    :target: https://nuts-documentation.readthedocs.io/projects/nuts--node/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://codecov.io/gh/nuts-foundation/nuts-node/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/nuts-foundation/nuts-node
    :alt: Code coverage

.. image:: https://api.codeclimate.com/v1/badges/69f77bd34f3ac253cae0/maintainability
   :target: https://codeclimate.com/github/nuts-foundation/nuts-node/maintainability
   :alt: Maintainability

Dependencies
************

Go >= 1.15 is required.

Running tests
*************

Tests can be run by executing

.. code-block:: shell

    go test ./...

Building
********

Just use ``go build``.

Code Generation
***************

Code generation is used for generating mocks, OpenAPI client- and servers and gRPC services. To regenerate the code
run the `run-generators` target from the Makefile:

.. code-block:: shell

    make run-generators

The peer-to-peer API uses gRPC. To generate Go code from the protobuf specs you need the `protoc-gen-go` package:

.. code-block:: shell

    go get -u github.com/golang/protobuf/protoc-gen-go

README
******

The readme is auto-generated from a template and uses the documentation to fill in the blanks.

.. code-block:: shell

    make gen-readme

This script uses ``rst_include`` which is installed as part of the dependencies for generating the documentation.

Documentation
*************

To generate the documentation, you'll need python3, sphinx and a bunch of other stuff.
The documentation can be build by running

.. code-block:: shell

    /docs $ make html

Requirements for running sphinx
===============================

  - install python3
  - install pip3 (if it doesn't install automatically)
  - ``pip3 install sphinx``
  - ``pip3 install recommonmark``
  - ``pip3 install sphinx_rtd_theme``
  - ``pip3 install rst_include``
  - ``pip3 install sphinx-jsonschema``
  - ``pip3 install sphinxcontrib-httpdomain``

Configuration
*************

The Nuts-go library contains some configuration logic which allows for usage of configFiles, Environment variables and commandLine params transparently.
If a Nuts engine is added as Engine it'll automatically work for the given engine. It is also possible for an engine to add the capabilities on a standalone basis.
This allows for testing from within a repo.

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


Options
*******

The following options can be configured:

.. marker-for-config-options

========================================  ===================================================================================  ================================================================================================================================================================================
Key                                       Default                                                                              Description
========================================  ===================================================================================  ================================================================================================================================================================================
****
address                                   localhost:1323                                                                       Address and port the server will be listening to
configfile                                nuts.yaml                                                                            Nuts config file
identity                                                                                                                       Vendor identity for the node, mandatory when running in server mode. Must be in the format: urn:oid:1.3.6.1.4.1.54851.4:<number>
mode                                      server                                                                               Mode the application will run in. When 'cli' it can be used to administer a remote Nuts node. When 'server' it will start a Nuts node. Defaults to 'server'.
strictmode                                false                                                                                When set, insecure settings are forbidden.
verbosity                                 info                                                                                 Log level (trace, debug, info, warn, error)
**Auth**
auth.actingPartyCn                                                                                                             The acting party Common name used in contracts
auth.address                              localhost:1323                                                                       Interface and port for http server to bind to
auth.enableCORS                           false                                                                                Set if you want to allow CORS requests. This is useful when you want browsers to directly communicate with the nuts node.
auth.irmaConfigPath                                                                                                            path to IRMA config folder. If not set, a tmp folder is created.
auth.irmaSchemeManager                    pbdf                                                                                 The IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'
auth.mode                                                                                                                      server or client, when client it does not start any services so that CLI commands can be used.
auth.publicUrl                                                                                                                 Public URL which can be reached by a users IRMA client
auth.skipAutoUpdateIrmaSchemas            false                                                                                set if you want to skip the auto download of the irma schemas every 60 minutes.
**ConsentBridgeClient**
cbridge.address                           http://localhost:8080                                                                API Address of the consent bridge
**ConsentStore**
cstore.address                            localhost:1323                                                                       Address of the server when in client mode
cstore.connectionstring                   \:memory:                                                                             Db connectionString
cstore.mode                                                                                                                    server or client, when client it uses the HttpClient
**Crypto**
crypto.fspath                             ./                                                                                   when file system is used as storage, this configures the path where keys are stored (default .)
crypto.keysize                            2048                                                                                 number of bits to use when creating new RSA keys
crypto.storage                            fs                                                                                   storage to use, 'fs' for file system (default)
**Events octopus**
events.autoRecover                        false                                                                                Republish unfinished events at startup
events.connectionstring                   file::memory:?cache=shared                                                           db connection string for event store
events.incrementalBackoff                 8                                                                                    Incremental backoff per retry queue, queue 0 retries after 1 second, queue 1 after {incrementalBackoff} * {previousDelay}
events.maxRetryCount                      5                                                                                    Max number of retries for events before giving up (only for recoverable errors
events.natsPort                           4222                                                                                 Port for Nats to bind on
events.purgeCompleted                     false                                                                                Purge completed events at startup
events.retryInterval                      60                                                                                   Retry delay in seconds for reconnecting
**Network**
network.bootstrapNodes                                                                                                         Space-separated list of bootstrap nodes (`<host>:<port>`) which the node initially connect to.
network.certFile                                                                                                               PEM file containing the certificate this node will identify itself with to other nodes. If not set, the Nuts node will attempt to load a TLS certificate from the crypto module.
network.certKeyFile                                                                                                            PEM file containing the key belonging to this node's certificate. If not set, the Nuts node will attempt to load a TLS certificate from the crypto module.
network.grpcAddr                          \:5555                                                                                Local address for gRPC to listen on.
network.publicAddr                                                                                                             Public address (of this node) other nodes can use to connect to it. If set, it is registered on the nodelist.
network.databaseFile                      network.db                                                                           Path to BBolt database file for storage of the network.
network.trustStoreFile                                                                                                         PEM file containing the trusted CA certificates for authenticating remote gRPC servers.
network.advertHashesInterval              2000                                                                                 Interval (in milliseconds) that specifies how often the node should broadcast its last hashes to other nodes.
**VDR**
vdr.clientTimeout                         10                                                                                   Time-out for the client in seconds (e.g. when using the CLI), default: 10
vdr.datadir                               ./data                                                                               Location of data files, default: ./data
**Validation**
fhir.schemapath                                                                                                                location of json schema, default nested Asset
===========================================================================================================================  ================================================================================================================================================================================

