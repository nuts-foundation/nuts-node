-- +goose ENVSUB ON
-- +goose Up
-- https://github.com/nuts-foundation/nuts-node/pull/3391
-- Renames status_list_credential.expanded to issued_credential
-- SQL Server does not support RENAME COLUMN, so we have to create a new column and copy the data over
alter table status_list_credential add bitstring $TEXT_TYPE;
update status_list_credential set bitstring = expanded;
alter table status_list_credential drop expanded;

-- +goose Down
alter table status_list_credential add expanded $TEXT_TYPE;
update status_list_credential set expanded = bitstring;
alter table status_list_credential drop bitstring;
