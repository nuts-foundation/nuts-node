nuts-node
#########

Distributed registry for storing and querying health care providers their vendors and technical endpoints.

.. image:: https://circleci.com/gh/nuts-foundation/nuts-node.svg?style=svg
    :target: https://circleci.com/gh/nuts-foundation/nuts-node
    :alt: Build Status

.. image:: https://readthedocs.org/projects/nuts-node/badge/?version=latest
    :target: https://nuts-node.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://codecov.io/gh/nuts-foundation/nuts-node/branch/master/graph/badge.svg?style=svg
    :target: https://codecov.io/gh/nuts-foundation/nuts-node
    :alt: Code coverage

.. image:: https://api.codeclimate.com/v1/badges/69f77bd34f3ac253cae0/maintainability
   :target: https://codeclimate.com/github/nuts-foundation/nuts-node/maintainability
   :alt: Maintainability

.. image:: https://github.com/nuts-foundation/nuts-node/actions/workflows/build-images.yaml/badge.svg
   :target: https://github.com/nuts-foundation/nuts-node/actions/workflows/build-images.yaml
   :alt: Build Docker images

Requirements
************

Go >= 1.16 is required.

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


Ordering
********

Command line parameters have the highest priority, then environment variables, then parameters from the configfile and lastly defaults.
The location of the configfile is determined by the environment variable ``NUTS_CONFIGFILE`` or the commandline parameter ``--configfile``. If both are missing the default location ``./nuts.yaml`` is used.

Server options
**************

The following options can be configured on the server:

.. marker-for-config-options

============================  ================  =======================================================================================================================================================================================================================
Key                           Default           Description
============================  ================  =======================================================================================================================================================================================================================
configfile                    nuts.yaml         Nuts config file
datadir                       ./data            Directory where the node stores its files.
strictmode                    false             When set, insecure settings are forbidden.
verbosity                     info              Log level (trace, debug, info, warn, error)
http.default.address          \:1323             Address and port the server will be listening to
http.default.cors.origin      []                When set, enables CORS from the specified origins for the on default HTTP interface.
**Auth**
auth.contractvalidators       [irma,uzi,dummy]  sets the different contract validators to use
auth.irma.autoupdateschemas   true              set if you want automatically update the IRMA schemas every 60 minutes.
auth.irma.schememanager       pbdf              IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'.
auth.publicurl                                  public URL which can be reached by a users IRMA client, this should include the scheme and domain: https://example.com. Additional paths should only be added if some sort of url-rewriting is done in a reverse-proxy.
**Crypto**
crypto.storage                fs                Storage to use, 'fs' for file system, default: fs
**Network**
network.adverthashesinterval  2000              Interval (in milliseconds) that specifies how often the node should broadcast its last hashes to other nodes.
network.bootstrapnodes        []                Comma-separated list of bootstrap nodes (`<host>:<port>`) which the node initially connect to.
network.certfile                                PEM file containing the server certificate for the gRPC server. Required when `enableTLS` is `true`.
network.certkeyfile                             PEM file containing the private key of the server certificate. Required when `network.enabletls` is `true`.
network.enabletls             true              Whether to enable TLS for incoming and outgoing gRPC connections. If set to `true` (which is default) `certfile` and `certkeyfile` MUST be configured.
network.grpcaddr              \:5555             Local address for gRPC to listen on. If empty the gRPC server won't be started and other nodes will not be able to connect to this node (outbound connections can still be made).
network.truststorefile                          PEM file containing the trusted CA certificates for authenticating remote gRPC servers.
============================  ================  =======================================================================================================================================================================================================================

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

