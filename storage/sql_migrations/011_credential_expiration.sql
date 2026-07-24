-- +goose Up
-- expiration_date is the credential's expirationDate as seconds since Unix epoch. Credentials without
-- an expirationDate get a far-future sentinel (9999-12-31) rather than null; null marks an existing
-- row not yet backfilled. The application backfills existing rows after migration.
alter table credential add expiration_date integer null;
create index idx_credential_expiration_date on credential (expiration_date);

-- +goose Down
drop index idx_credential_expiration_date;
alter table credential drop column expiration_date;
