.. _nuts-node-development:

Nuts node development
#####################

Requirements
************

.. marker-for-readme

Go >= 1.17 is required.

Building
********

Just use ``go build``.

Building for exotic environments
================================

You can build and run the Nuts node on more exotic environments, e.g. Raspberry Pis:

* 32-bit ARMv6 (Raspberry Pi Zero): ``env GOOS=linux GOARCH=arm GOARM=6 go build``

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
