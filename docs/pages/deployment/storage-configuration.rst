.. _storage-configuration:

Storage Configuration
#####################

The Nuts node supports different backends for storage. This page describes the particulars of each backend and how to configure it.

.. note::

    The node does not automatically back up your data or keys.
    This is something :ref:`you need to set up <backup-restore>` regardless the backend you use.

.. note::

    Clustering is not supported. Even if you use a backend that supports concurrent access (e.g. Redis),
    you can't have multiple Nuts nodes use the same data storage.

Data
****

Data is everything your node produces and stores, except private keys. It is also everything that is produced and published by other nodes in the network.

.. note::

    Even if you configure external data storage (Redis), certain data is still stored on disk (e.g. search indexes).
    Although this does not need to be in backup, depending on the network state size it can take a long time to rebuild it.
    So you should always retain the data directory when restarting or upgrading the node.

BBolt
=====

By default, all data (aside from private keys) is stored on disk using BBolt. You don't need to configure anything to get it working, but don't forget the backup procedure.
If an alternative data store is configured (e.g. Redis), volatile data (projections that are generally quick to rebuild) is still stored in BBolt.
You can back up volatile data, but it is not required.

Redis
=====

If the node is configured to use Redis it stores network state in the configured Redis server.
To use Redis, configure ``storage.redis.address``.
You can configure username/password authentication using ``storage.redis.username`` and ``storage.redis.password``.

If you need to prefix the keys (e.g. you have multiple Nuts nodes using the same Redis server) you can set ``storage.redis.database``
with an alphanumeric string. All keys written to Redis will then have that prefix followed by a separator.

You can connect to your Redis server over TLS by specifying a Redis connection URL in ``storage.redis.address``,
e.g.: ``rediss://database.mycluster.com:1234567``.
The server's certificate will be verified against the OS' CA bundle.

.. note::

    Make sure to `configure persistence for your Redis server <https://redis.io/docs/manual/persistence/>`_.

Redis Sentinel
^^^^^^^^^^^^^^

You can enable Redis Sentinel by configuring ``storage.redis.sentinel``. The following properties must be configured:

- ``master`` must contain the name of the Redis Sentinel master
- ``nodes`` must contain a list of Redis Sentinel to initially connect to.

If using a connection URL for ``storage.redis.address`` (e.g. to enable TLS) the host in the URL won't be used.
However, it still must be provided but can be any arbitrary value.
Other configuration and connection URL parameters (not specific) to Sentinel still apply.

.. code-block:: yaml

    storage:
      redis:
        address: redis://irrelevant
        sentinel:
          master: mymaster
          nodes:
            - instance1:1234
            - instance2:5678

Review the configuration reference for additional Redis Sentinel configuration parameters.

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
----------------------------

Migrating your private keys from the filesystem to Vault is relatively easy: just upload the keys to Vault under ``kv/nuts-private-keys``.

Alternatively you can use the ``fs2vault`` crypto command, which takes the directory containing the private keys as argument (the example assumes the container is called *nuts-node* and *NUTS_DATADIR=/opt/nuts/data*):

.. code-block:: shell

    docker exec nuts-node nuts crypto fs2vault /opt/nuts/data/crypto

In any case, make sure the key-value secret engine exists before trying to migrate (default engine name is ``kv``).

External Store API
==================

.. note::

    The external store API is still experimental and may change in the future.


The Nuts node can be configured to use an external store for private keys. This allows you to use your own key management system. The external store must implement the Nuts Secret store API specification. This OpenAPI specification is available from the `Secret Store API repository <https://github.com/nuts-foundation/secret-store-api>`__ on GitHub.

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


Trusted issuers
***************

The Nuts node stores your trusted issuers in ``<datadir>/vcr/trusted_issuers.yaml``.
This file should be kept persistent and should be part of the backup procedure.
