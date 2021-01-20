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

    make gen-api

Generating Mocks
****************

These mocks are used by other modules

.. code-block:: shell

	make gen-mocks
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