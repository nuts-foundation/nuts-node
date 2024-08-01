.. _nuts-cli-reference:

CLI Command Reference
#####################

There are 2 types of commands: server command and client commands. Server commands (e.g. ``nuts server``) can only be run on the system where the node is (or will be) running, because they require the node's config. Client commands are used to remotely administer a Nuts node and require the node's API address.


nuts config
^^^^^^^^^^^

Prints the current config

::

  nuts config [flags]


nuts crypto fs2vault
^^^^^^^^^^^^^^^^^^^^

Imports private keys from filesystem based storage into Vault. The given directory must contain the private key files.The Nuts node must be configured to use Vault as crypto storage. Can only be run on the local Nuts node, from the directory where nuts.yaml resides.

::

  nuts crypto fs2vault [directory] [flags]


nuts server
^^^^^^^^^^^

Starts the Nuts server

::

  nuts server [flags]


