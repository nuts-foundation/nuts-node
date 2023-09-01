.. _backup-restore:

Backup & restore procedures
###########################

The Nuts node supports different backends for storing data. This page describes the backup and restore procedures per backend.
A restore procedure may contain additional steps to take besides restoring the data from backup.

Backup
******

Private keys
============

The private keys are the most important of all data.
When lost, all data has to be recreated which might include asking customer to re-sign certain documents.
The Nuts node provides two ways of storing private keys: local filesystem and via Hashicorp Vault.
Vault is the recommended store for storing private keys in a production environment.
Please consult the `Vault documentation <https://learn.hashicorp.com/tutorials/vault/sop-backup>`_ on how to manage your backups.

BBolt
=====

The default storage for a Nuts node is BBolt. BBolt is a key-value store that stores data on disk.
Private keys are not stored in BBolt and have their own backup/restore procedure.
A BBolt store can only be accessed by a single process, so backups have to be managed by the Nuts node.

By default, the BBolt store isn't backed up. To enable backups add these configuration options:

.. code-block:: yaml

    storage:
      bbolt:
        backup:
          directory: /opt/nuts/shelf
          interval: 1h

The ``directory`` must point to a local or mounted directory.
The ``interval`` must be formatted as a number and time unit. Valid time units are ``s`` (seconds), ``m`` (minutes), ``h`` (hours).

The Nuts node will place backups at the set interval in the configured directory. It creates sub-directories for different components.
The file names follow the same structure as in the node's ``datadir``.
The backup process will write to a temporary file first and when done rename that file.

The backup process will only keep a single file per store.
If you want to keep hourly, daily, and weekly backups, you can achieve this with tools like ``rsync`` and ``rsnapshot`` (or others).

Redis
=====

Refer to the `Redis documentation <https://redis.io/docs/manual/persistence/>`_ on how to deal with backups.

Other
=====

Additionally, the list of trusted VC issuers must be backed up as well.
Trusted issuers of VCs are stored in  ``vcr/trusted_issuers.yaml`` inside the ``datadir`` directory.
If the contents of this file is your primary store for trusted issuers (you're not managing them in an external administrative system), make sure to make a backup.

Restore
*******

To restore a backup, follow the following steps:

1. shutdown the node
2. remove the following directories from the ``datadir``: ``events``, ``network``, ``vcr``, and ``vdr``
3. follow the restore procedure for your storage (BBolt, Redis, Hashicorp Vault)
4. restore the ``vcr/trusted_issuers.yaml`` file inside ``datadir``
5. start your node

BBolt
=====

In step 3, copy the following files from your backup to the ``datadir`` (keep the directory structure)

 - ``network/data.db``
 - ``vcr/wallet.db``
 - ``vcr/backup-credentials.db``
 - ``vcr/backup-issued-credentials.db``
 - ``vcr/backup-revoked-credentials.db``
 - ``vdr/didstore.db``