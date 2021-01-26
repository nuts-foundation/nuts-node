.. _nuts-node-development:

Nuts node development
#####################

.. marker-for-readme

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