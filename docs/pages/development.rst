.. _nuts-node-development:

Nuts node development
#####################

.. marker-for-readme

Dependencies
************

This projects is using go modules, so version > 1.12 is recommended. 1.10 would be a minimum.

Running tests
*************

Tests can be run by executing

.. code-block:: shell

    go test ./...

Building
********

Just use ``go build``.

The server and client API is generated from the open-api spec:

.. code-block:: shell

    oapi-codegen -generate types,server,client -package v1 docs/_static/crypto/v1.yaml > crypto/api/v1/generated.go
    oapi-codegen -generate types,server,client -package v1 docs/_static/did/v1.yaml > did/api/v1/generated.go

Generating Mocks
****************

These mocks are used by other modules

.. code-block:: shell

    mockgen -destination=crypto/mock/mock_crypto.go -package=mock -source=crypto/interface.go KeyStore

README
******

The readme is auto-generated from a template and uses the documentation to fill in the blanks.

.. code-block:: shell

    ./generate_readme.sh

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