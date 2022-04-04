nuts-node
#########

Distributed registry for storing and querying health care providers their vendors and technical endpoints.

See the `documentation <https://nuts-node.readthedocs.io/en/latest/>`_ for how to set up, integrate and use the Nuts node.

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

Hello, World!
^^^^^^^^^^^^^

The simplest way to spin up the Nuts stack is by using the setup provided by `nuts-network-local <https://github.com/nuts-foundation/nuts-network-local>`_.
The setup is meant for development purposes and starts a Nuts node, "Demo EHR", "Registry Admin Demo" for administering your vendor and care organizations and a HAPI server to exchange FHIR data.

To get started, clone the repository and run the following commands to start the stack:

.. code-block:: shell

    cd single
    docker-compose pull
    docker-compose up

After the services have started you can try the following endpoints:

- `Nuts Node status page <http://localhost:1323/status/diagnostics/>`_.
- `Registry Admin Demo login <http://localhost:1304/>`_ (default password: "demo").
- `Demo EHR login <http://localhost:1303/>`_ (default password: "demo").

Development
^^^^^^^^^^^

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
^^^^^^^^^^^^^

The simplest way to spin up the Nuts stack is by using the setup provided by `nuts-network-local <https://github.com/nuts-foundation/nuts-network-local>`_.
The setup is meant for development purposes and starts a Nuts node, "Demo EHR", "Registry Admin Demo" for administering your vendor and care organizations and a HAPI server to exchange FHIR data.

To get started, clone the repository and run the following commands to start the stack:

.. code-block:: shell

    cd single
    docker-compose pull
    docker-compose up

After the services have started you can try the following endpoints:

- `Nuts Node status page <http://localhost:1323/status/diagnostics/>`_.
- `Registry Admin Demo login <http://localhost:1304/>`_ (default password: "demo").
- `Demo EHR login <http://localhost:1303/>`_ (default password: "demo").

CLI options
^^^^^^^^^^^

The following options can be supplied when running CLI commands:

=======  ==============  =====================================================================================================================================================================
Key      Default         Description
=======  ==============  =====================================================================================================================================================================
address  localhost:1323  Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended.
timeout  10s             Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.
=======  ==============  =====================================================================================================================================================================

