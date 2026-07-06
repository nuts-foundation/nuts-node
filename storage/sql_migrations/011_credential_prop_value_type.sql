-- +goose ENVSUB ON
-- +goose Up
-- credential_prop.value holds arbitrary credentialSubject property values, which have no natural
-- max length, so the varchar(500) cap from 001_credential.sql is widened to an unbounded text type.
alter table credential_prop $ALTER_COLUMN value $ALTER_COLUMN_TYPE $TEXT_TYPE;

-- +goose Down
alter table credential_prop $ALTER_COLUMN value $ALTER_COLUMN_TYPE varchar(500);
