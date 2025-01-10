.. _nuts-node-development:

Nuts node development
#####################

Requirements
************

.. marker-for-readme

.. |gover| image:: https://img.shields.io/github/go-mod/go-version/nuts-foundation/nuts-node
    :alt: GitHub go.mod Go version

|gover| or higher is required.

Building
********

Just use ``go build``.

ES256 Koblitz support
=====================

To enable ES256K (Koblitz) support, you need to build with the ``jwx_es256k`` tag:

.. code-block:: shell

    go build -tags jwx_es256k

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

Documentation
=============

The documentation is automatically build on readthedocs based on the config in ``.readthedocs.yaml``.
All files to be included can be generated using:

.. code-block:: shell

    make cli-docs

This regenerates files from code, and the ``README.rst`` file which requires python package ``rst-include`` (``pip install rst-include``).

If needed, you can also build the documentation locally in ``/docs/_build`` using docker:

.. code-block:: shell

    docker build -t local/nuts-node-docs ./docs
    docker run --rm -v ./docs:/docs local/nuts-node-docs