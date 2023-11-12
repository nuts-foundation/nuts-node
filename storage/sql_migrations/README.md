This directory contains SQL schema migrations, run at startup of the node.

Refer to https://github.com/golang-migrate/migrate/blob/master/MIGRATIONS.md on how to write migrations.

Files should be named according to the following: `<number>_<short engine name>_<table/feature name>.<up|down>.sql`.
For instance: `2_usecase_list.up.sql`.

AVOID changing migrations in master (unless the migration breaks the node horribly) for those running a `master` version.
DO NOT alter migrations in a released version: it might break vendor deployments or cause data corruption.