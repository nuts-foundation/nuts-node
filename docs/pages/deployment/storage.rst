.. _storage-configuration:

Storage
#######

The Nuts node supports different backends for storage. This page describes the particulars of each backend and how to configure it.

.. note::

    This page does not describe how to configure storage when using ``did:nuts`` DIDs and the Nuts gRPC network,
    which require specific storage configuration. If your use case require these features, refer to the v5 documentation for configuration storage.

The Nuts node uses two types of storage:

- SQL database for storing DID documents and Verifiable Credentials.
- Private key storage for securely storing cryptographic private keys.

The Nuts node does not backup your data, remember to backup the data in these storages regularly.
Also remember to test your backup and restore procedure.

SQL database
************

Currently supported SQL databases are Postgres, MySQL, Microsoft SQL Server, Microsoft Azure SQL Server, and SQLite.
The database of your preference can be set by configuring a connection string in ``storage.sql.connection``.
Only in non-strictmode, if no connection string is set this will default to SQLite in a file called ``sqlite.db`` in the configured data directory.

Connection strings must be in the following format:

.. code-block:: none

    protocol://username:password@host:port/database_name?options

Refer to the documentation of the driver for the database you are using for the correct connection string format:

- Postgres `github.com/jackc/pgx <https://github.com/jackc/pgx?tab=readme-ov-file#example-usage>`_ (e.g. ``postgres://user:password@localhost:5432/dbname?sslmode=disable``)
- MySql: `github.com/go-sql-driver/mysql <https://github.com/go-sql-driver/mysql?tab=readme-ov-file#dsn-data-source-name>`_ (e.g. ``mysql://user:password@tcp(localhost:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local``)
- MS SQL Server: `github.com/microsoft/go-mssqldb <https://github.com/microsoft/go-mssqldb>`_ (e.g. ``sqlserver://user:password@localhost:1433?database=dbname``)
- Azure SQL Server: `github.com/microsoft/go-mssqldb <https://github.com/microsoft/go-mssqldb>`_ (e.g. ``azuresql://server=awesome-server;port=1433;database=awesome-db;fedauth=ActiveDirectoryDefault;``)
- SQLite (e.g. ``sqlite:file:/some/path/sqlite.db?_pragma=foreign_keys(1)&journal_mode(WAL)``)

.. warning::

    Usage of SQLite is not recommended for production environments.
    Connections to a SQLite DB are restricted to 1, which will lead to severe performance reduction.

Private Keys
************

Your node generates and stores private keys when you create DID documents or add new keys to it.
Private keys are very sensitive! If you leak them, others could impersonate your identity and possibly worse.
If you lose them you need to re-create your identity, which could be very cumbersome.
Thus, it's very important the private key storage is both secure and reliable.

Filesystem
==========

This is the default backend but not recommended for production. It stores keys unencrypted on disk.
Make sure to include the directory in your backups and keep these in a safe place.
If you want to use filesystem in strict mode, you have to set it explicitly, otherwise the node fails during startup.

Microsoft Azure Key Vault
=========================

This storage backend uses Microsoft Azure's Key Vault. The following rules apply:

- To store private keys in an Azure Key Vault HSM, set ``crypto.azurekv.hsm`` to ``true``.
- Keys created through this storage backend are marked as non-exportable.
- Azure Key Vault storage can't be used for encrypting ``did:nuts`` private credentials or for data encryption.

The following credential options are available for authentication:
- ``managed_identity``: authenticate using ManagedIdentity credential (recommended, because default credential often times out when deployed in Azure).
- ``default``: authenticate using the DefaultChain credential.
At least the ``AZURE_TENANT_ID`` and ``AZURE_CLIENT_ID`` (for user assigned identities) need to be set in the environment.
Refer to the `Azure SDK for Go documentation <https://github.com/Azure/azure-sdk-for-go/wiki/Set-up-Your-Environment-for-Authentication>`_ for more information.

HashiCorp Vault
===============

This storage backend uses the `Vault KV version 1 store <https://www.vaultproject.io/docs/secrets/kv/kv-v1>`_.
The path prefix defaults to ``kv`` and can be configured using the ``crypto.vault.pathprefix`` option.
There needs to be a KV Secrets Engine (v1) enabled under this prefix path.

All private keys are stored under the path ``<prefix>/nuts-private-keys/*``.
Each key is stored under a UUID, resulting in a full key path like ``kv/nuts-private-keys/bfedb25f-a218-4687-9acf-29a263ed4c50`` (old keys are stored under the kid).
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


.. warning::

    The external store API is deprecated and will be removed in the next major release.
    Anyone with access to the external store can read/write your private keys, so make sure it's properly secured and only the Nuts node can access it.


The Nuts node can be configured to use an external store for private keys. This allows you to use your own key management system.
The external store must implement the Nuts Secret store API specification.
This OpenAPI specification is available from the `Secret Store API repository <https://github.com/nuts-foundation/secret-store-api>`__ on GitHub.
