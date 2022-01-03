nuts-node
#########

Distributed registry for storing and querying health care providers their vendors and technical endpoints.

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

Requirements
************

Go >= 1.17 is required.

Building
********

Just use ``go build``.

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

Docs Generation
***************

To generate the documentation, you'll need ``python3``, ``sphinx`` and a bunch of other stuff.
After you have installed ``python3`` (and ``pip3`` if this not already installed) run

.. code-block:: shell

    pip3 install -r docs/requirements.txt


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
*************

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
To provide multiple values through flags or environment variables you can separate them with a comma (``,``).

Ordering
********

Command line parameters have the highest priority, then environment variables, then parameters from the configfile and lastly defaults.
The location of the configfile is determined by the environment variable ``NUTS_CONFIGFILE`` or the commandline parameter ``--configfile``. If both are missing the default location ``./nuts.yaml`` is used.

Server options
**************

The following options can be configured on the server:

.. marker-for-config-options

=========================================  ================  ====================================================================================================================================================================================================================================
Key                                        Default           Description
=========================================  ================  ====================================================================================================================================================================================================================================
configfile                                 nuts.yaml         Nuts config file
datadir                                    ./data            Directory where the node stores its files.
loggerformat                               text              Log format (text, json)
strictmode                                 false             When set, insecure settings are forbidden.
verbosity                                  info              Log level (trace, debug, info, warn, error)
http.default.address                       \:1323             Address and port the server will be listening to
http.default.cors.origin                   []                When set, enables CORS from the specified origins for the on default HTTP interface.
**Auth**
auth.clockskew                             5000              Allowed JWT Clock skew in milliseconds
auth.contractvalidators                    [irma,uzi,dummy]  sets the different contract validators to use
auth.http.timeout                          30                HTTP timeout (in seconds) used by the Auth API HTTP client
auth.irma.autoupdateschemas                true              set if you want automatically update the IRMA schemas every 60 minutes.
auth.irma.schememanager                    pbdf              IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'.
auth.publicurl                                               public URL which can be reached by a users IRMA client, this should include the scheme and domain: https://example.com. Additional paths should only be added if some sort of url-rewriting is done in a reverse-proxy.
**Crypto**
crypto.storage                             fs                Storage to use, 'fs' for file system, vaultkv for Vault KV store, default: fs.
crypto.vault.address                                         The Vault address. If set it overwrites the VAULT_ADDR env var.
crypto.vault.pathprefix                    kv                The Vault path prefix. default: kv.
crypto.vault.token                                           The Vault token. If set it overwrites the VAULT_TOKEN env var.
**Event manager**
events.nats.hostname                       localhost         Hostname for the NATS server
events.nats.port                           4222              Port where the NATS server listens on
events.nats.storagedir                                       Directory where file-backed streams are stored in the NATS server
events.nats.timeout                        30                Timeout for NATS server operations
**Network**
network.bootstrapnodes                     []                List of bootstrap nodes (`<host>:<port>`) which the node initially connect to.
network.certfile                                             PEM file containing the server certificate for the gRPC server. Required when `enableTLS` is `true`.
network.certkeyfile                                          PEM file containing the private key of the server certificate. Required when `network.enabletls` is `true`.
network.disablenodeauthentication          false             Disable node DID authentication using client certificate, causing all node DIDs to be accepted. Unsafe option, only intended for workshops/demo purposes. Not allowed in strict-mode.
network.enabletls                          true              Whether to enable TLS for incoming and outgoing gRPC connections. When `certfile` or `certkeyfile` is specified it defaults to `true`, otherwise `false`.
network.grpcaddr                           \:5555             Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made).
network.nodedid                                              Specifies the DID of the organization that operates this node, typically a vendor for EPD software. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.
network.truststorefile                                       PEM file containing the trusted CA certificates for authenticating remote gRPC servers.
network.v1.advertdiagnosticsinterval       5000              Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable).
network.v1.adverthashesinterval            2000              Interval (in milliseconds) that specifies how often the node should broadcast its last hashes to other nodes.
network.v1.collectmissingpayloadsinterval  60000             Interval (in milliseconds) that specifies how often the node should check for missing payloads and broadcast its peers for it (specify 0 to disable). This check might be heavy on larger DAGs so make sure not to run it too often.
=========================================  ================  ====================================================================================================================================================================================================================================

This table is automatically generated using the configuration flags in the core and engines. When they're changed
the options table must be regenerated using the Makefile:

.. code-block:: shell

    $ make update-docs

CLI options
***********

The following options can be supplied when running CLI commands:

=======  ==============  =====================================================================================================================================================================
Key      Default         Description
=======  ==============  =====================================================================================================================================================================
address  localhost:1323  Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended.
timeout  10s             Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.
=======  ==============  =====================================================================================================================================================================

