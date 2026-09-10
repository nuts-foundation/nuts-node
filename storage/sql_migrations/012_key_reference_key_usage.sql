-- +goose Up
-- key_usage is a bitmask of the DIDKeyFlags the key can actually be used for, using the same
-- encoding as did_verification_method.key_types:
-- 0x01 - AssertionMethod
-- 0x02 - Authentication
-- 0x04 - CapabilityDelegation
-- 0x08 - CapabilityInvocation
-- 0x10 - KeyAgreement
-- Defaults to 0 ("not yet determined") rather than assuming every existing key supports every
-- usage: crypto.Migrate() sets it to the currently configured backend's usage for every row still
-- at 0, on every startup.
alter table key_reference
    add column key_usage SMALLINT not null default 0;

-- +goose Down
alter table key_reference
    drop column key_usage;
