.. _backup-restore:

Backup & restore procedures
###########################

The Nuts node supports different backends for storing data. This page describes the backup and restore procedures per backend.
A restore procedure may contain additional steps to take besides restoring the data from backup.

Private keys
************

The private keys are the most important of all data.
When lost, all data has to be recreated which might include asking customer to resign certain documents.
The Nuts node provides two ways of storing private keys: local filesystem and via Hashicorp Vault.
Vault is the recommended store for storing private keys in a production environment.
Please consult the Vault documentation on how to manage your backups.

BBolt
*****

The default storage for a Nuts node is BBolt. BBolt is a key-value store that stores data on disk.
A BBolt store can only be accessed by a single process.
Private keys are not stored in BBolt and have their own backup/restore procedure.

Backup
======

By default, the BBolt store isn't backed up. To enable backups add these configuration options:

.. code-block:: yaml

    storage:
      databases:
        bbolt:
          backup:
            directory: /opt/nuts/shelf
            interval: 1h

The ``directory`` must point to a local or mounted directory.
The ``interval`` must be formatted as a number and time unit. Valid time units are ``s`` (seconds), ``m`` (minutes), ``h`` (hours).

The Nuts node will place backups at the set interval in the configured directory. It'll create sub-directories for different components.
The file names are the same as in the node's ``datadir``.
The backup process will write to a temporary file first and when done rename that file.

The backup process will only keep a single file per store.
If you want to keep hourly, daily and weekly backups, you'll have to solve this by using tools like ``rsync`` and ``rsnapshot`` (or others).

Restore
=======

To restore a backup, follow the following steps:

- shutdown the node.
- remove the following directories from the ``datadir``: ``events``, ``network``, ``vcr`` and ``vdr``
- copy ``network/data.db``, ``vcr/issued-credentials-backup.db`` and ``vdr/didstore.db`` from your backup to the ``datadir`` (keep directory structure).
- start your node
- make an empty POST call to ``/internal/network/v1/reprocess?type=application/vc+json``
- make an empty POST call to ``/internal/network/v1/reprocess?type=application/ld+json;type=revocation``

When making the API calls, make sure you use the proper URL escaping.
Reprocess calls return immediately and will do the work in the background.
