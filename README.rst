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

============================  ==============  =================================================================================================================================================================================
Key                           Default         Description
============================  ==============  =================================================================================================================================================================================
****
address                       localhost:1323  Address and port the server will be listening to
configfile                    nuts.yaml       Nuts config file
identity                                      Vendor identity for the node, mandatory when running in server mode. Must be in the format: urn:oid:1.3.6.1.4.1.54851.4:<number>
mode                          server          Mode the application will run in. When 'cli' it can be used to administer a remote Nuts node. When 'server' it will start a Nuts node. Defaults to 'server'.
strictmode                    false           When set, insecure settings are forbidden.
verbosity                     info            Log level (trace, debug, info, warn, error)
**Crypto**
crypto.fspath                 ./              When file system is used as storage, this configures the path where key material and the truststore are persisted, default: ./
crypto.storage                fs              Storage to use, 'fs' for file system, default: fs
**Network**
network.advertHashesInterval  2000            Interval (in milliseconds) that specifies how often the node should broadcast its last hashes to other nodes.
network.bootstrapNodes                        Space-separated list of bootstrap nodes (`<host>:<port>`) which the node initially connect to.
network.certFile                              PEM file containing the server certificate for the gRPC server. Required when `enableTLS` is `true`.
network.certKeyFile                           PEM file containing the private key of the server certificate. Required when `enableTLS` is `true`.
network.databaseFile          network.db      File path to the network database.
network.enableTLS             true            Whether to enable TLS for inbound gRPC connections. If set to `true` (which is default) `certFile` and `certKeyFile` MUST be configured.
network.grpcAddr              \:5555           Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made).
network.publicAddr                            Public address (of this node) other nodes can use to connect to it. If set, it is registered on the nodelist.
network.trustStoreFile                        PEM file containing the trusted CA certificates for authenticating remote gRPC servers.
**Verifiable Data Registry**
vdr.clientTimeout             10              Time-out for the client in seconds (e.g. when using the CLI), default: 10
vdr.datadir                   ./data          Location of data files, default: ./data
============================  ==============  =================================================================================================================================================================================

