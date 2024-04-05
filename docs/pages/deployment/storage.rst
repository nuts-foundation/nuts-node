.. _storage-configuration:

Storage
#######

The Nuts node supports different backends for storage. This page describes the particulars of each backend and how to configure it.

.. note::

    This page does not describe how to configure storage when using ``did:nuts`` DIDs and/or the Nuts gRPC network,
    which require specific storage configuration. If your use case require these features, refer to the v5 documentation for configuration storage.

The Nuts node uses two types of storage:

- SQL database for storing (``did:web``) DID documents and Verifiable Credentials.
- Private key storage for securely storing cryptographic private keys.

The Nuts node does not backup your data, remember to backup the data in these storages regularly.
Also remember to test your backup and restore procedure.

SQL database
************

By default, storage SQLite will be used in a file called ``sqlite.db`` in the configured data directory.
This can be overridden by configuring a connection string in ``storage.sql.connection``.
Other supported SQL databases are Postgres and MySQL.

Connection strings must be in the following format:

.. code-block:: none

    protocol://username:password@host:port/database_name?options

See the `dbmate documentation <https://github.com/amacneil/dbmate?tab=readme-ov-file#connecting-to-the-database>`_ for more information.

Examples:

- Postgres: ``postgres://user:password@localhost:5432/dbname?sslmode=disable``
- MySql: ``mysql://user:password@localhost:3306/dbname?charset=utf8mb4&parseTime=True&loc=Local``
- SQLite: ``sqlite:file:/some/path/sqlite.db?_journal_mode=WAL&_foreign_keys=on``

Private Keys
************

Your node generates and stores private keys when you create DID documents or add new keys to it.
Private keys are very sensitive! If you leak them, others could alter your presence on the Nuts network and possibly worse.
If you lose them you need to re-register your presence on the Nuts network, which could be very cumbersome.
Thus, it's very important the private key storage is both secure and reliable.

Filesystem
==========

This is the default backend but not recommended for production. It stores keys unencrypted on disk.
Make sure to include the directory in your backups and keep these in a safe place.
If you want to use filesystem in strict mode, you have to set it explicitly, otherwise the node fails during startup.

HashiCorp Vault
==============

This storage backend is the current recommended way of storing secrets. It uses the `Vault KV version 1 store <https://www.vaultproject.io/docs/secrets/kv/kv-v1>`_.
The path prefix defaults to ``kv`` and can be configured using the ``crypto.vault.pathprefix`` option.
There needs to be a KV Secrets Engine (v1) enabled under this prefix path.

All private keys are stored under the path ``<prefix>/nuts-private-keys/*``.
Each key is stored under the kid, resulting in a full key path like ``kv/nuts-private-keys/did:nuts:123#abc``.
A Vault token must be provided by either configuring it using the config ``crypto.vault.token`` or setting the VAULT_TOKEN environment variable.
The token must have a vault policy which has READ and WRITES rights on the path. In addition it needs to READ the token information "auth/token/lookup-self" which should be part of the default policy.

Migrating to Hashicorp Vault
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Migrating your private keys from the filesystem to Vault is relatively easy: just upload the keys to Vault under ``kv/nuts-private-keys``.

Alternatively you can use the ``fs2vault`` crypto command, which takes the directory containing the private keys as argument (the example assumes the container is called *nuts-node* and *NUTS_DATADIR=/opt/nuts/data*):

.. code-block:: shell

    docker exec nuts-node nuts crypto fs2vault /opt/nuts/data/crypto

In any case, make sure the key-value secret engine exists before trying to migrate (default engine name is ``kv``).

External Store API
==================

.. note::

    The external store API is still experimental and may change in the future.

.. warning::

    Anyone with access to the external store can read/write your private keys, so make sure it's properly secured and only the Nuts node can access it.


The Nuts node can be configured to use an external store for private keys. This allows you to use your own key management system.
The external store must implement the Nuts Secret store API specification.
This OpenAPI specification is available from the `Secret Store API repository <https://github.com/nuts-foundation/secret-store-api>`__ on GitHub.

Configuration
^^^^^^^^^^^^^

In order to use an external store, you need to set the ``crypto.storage`` option to ``external``. You also need to configure the ``crypto.external.address`` option to the address of the external store. The following example shows the typical configuration for a Nuts Vault proxy.

.. code-block:: yaml

    crypto:
      storage: external
      external:
        address: https://localhost:8210

Migrating to external storage
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you want to migrate your private keys from the filesystem to an external store, you can use the Nuts command line interface with the ``fs2external`` crypto command. It takes the directory containing the private keys as argument (the example assumes the container is called *nuts-node* and *NUTS_DATADIR=/opt/nuts/data*):

.. code-block:: shell

    docker exec nuts-node nuts crypto fs2external /opt/nuts/data/crypto

If you use the `vaultkv` store and want to start using the vault proxy, read the documentation of the Nuts Vault proxy.


Available external storage implementations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following list contains all the known implementations of the Nuts external store API:

- `Nuts Vault proxy <https://github.com/nuts-foundation/hashicorp-vault-proxy>`__. This is a proxy that integrates with Hashicorp Vault. It uses the Vault KV store to store the keys. The proxy is developed by the Nuts foundation and is available under an open source license.

If you want to build your own store, take a look at the documentation at :ref:`external-secret-store`.
