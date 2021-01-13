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

    oapi-codegen -generate types,server,client -package api docs/_static/example.yaml > api/generated.go

Generating Mocks
****************

These mocks are used by other modules

.. code-block:: shell

    mockgen -destination=mock/mock_example.go -package=mock -source=example.go

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

The resulting html will be available from ``docs/_build/html/index.html``

Configuration
*************

config stuff
============

