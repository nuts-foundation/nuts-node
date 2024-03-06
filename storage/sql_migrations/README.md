This directory contains SQL schema migrations, run at startup of the node.

Refer to https://github.com/amacneil/dbmate on how to write migrations.

Files should be named according to the following: `<number>_<short engine name>_<table/feature name>.sql`.
For instance: `002_usecase_list.sql`. Each file should contain `-- migrate:up` and `-- migrate:down`

AVOID changing migrations in master (unless the migration breaks the node horribly) for those running a `master` version.
DO NOT alter migrations in a released version: it might break vendor deployments or cause data corruption.

DID and ID column length are set at 370 and 415 characters:
- domain names have a max length of 253
- `did:web:` has length 8
- for an additional path for did:web we could define max label length=63 + 1 (:)
- for the identifier a base64 encoded sha256 (44 chars) or uuid v4 (36 chars) would suffice (+1 for :)

- in bytes this is 1480 and 1660 bytes for a 4byte utf8 representation.