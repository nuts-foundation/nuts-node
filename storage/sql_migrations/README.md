This directory contains SQL schema migrations, run at startup of the node.

Refer to https://github.com/golang-migrate/migrate/blob/master/MIGRATIONS.md on how to write migrations.

Files should be named according to the following: `<number>_<short engine name>_<table/feature name>.<up|down>.sql`.
For instance: `2_usecase_list.up.sql`.

Remember NOT to alter migrations that were included in released versions of the Nuts node: it might break vendor deployments or cause data corruption.