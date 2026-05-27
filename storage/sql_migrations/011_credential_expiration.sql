-- +goose Up
-- expiration_date is the credential's expirationDate as seconds since Unix epoch, null if the
-- credential does not expire. Existing rows are backfilled by the application after migration.
alter table credential add column expiration_date integer null;
create index idx_credential_expiration_date on credential (expiration_date);

-- +goose Down
drop index idx_credential_expiration_date;
alter table credential drop column expiration_date;
