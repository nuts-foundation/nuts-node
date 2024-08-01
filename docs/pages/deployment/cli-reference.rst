.. _nuts-cli-reference:

Server CLI Command Reference
############################

Aside from ``nuts server``, there are few other server commands that can be run. They can only be run on the system where the node is (or will be) running, because they require the node's config.
Refer to the configuration reference for how and what can be configured.


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


