.. _administering-your-node:

Administration using the CLI
############################

The Nuts executable this project provides can be used to both run a Nuts server (a.k.a. node) and administer a running
node remotely. This chapter explains how to administer your running Nuts node.

Prerequisites
*************

The following is needed to run a Nuts node:

1. Nuts executable for your platform, or a Nuts docker container.
2. The address of your running Nuts node. You can pass this using the `address` variable.

Commands
********

Run the executable without command or flags, or with the `help` command to find out what commands are supported:

.. code-block:: shell

    nuts

For example, to list all network transactions in your node (replace the value of `NUTS_ADDRESS` with the HTTP address of your Nuts node):

.. code-block:: shell

    NUTS_ADDRESS=my-node:8081 nuts network list

You can also use the Nuts docker image to run a command (against a remote Nuts node):

.. code-block:: shell

    docker run nutsfoundation/nuts-node --address=http://my-node:8081 network list

Or inside a running Nuts docker container (against the running Nuts node):

.. code-block:: shell

    docker exec <nuts-container-name> nuts network list

See :ref:`nuts-cli-reference` for the available commands.

.. marker-for-readme

The following options can be supplied when running CLI commands:

.. include:: ../client_options.rst
