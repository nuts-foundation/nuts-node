-- +goose Up
-- key_usage is a bitmask of the DIDKeyFlags the key can actually be used for, using the same
-- encoding as did_verification_method.key_types:
-- 0x01 - AssertionMethod
-- 0x02 - Authentication
-- 0x04 - CapabilityDelegation
-- 0x08 - CapabilityInvocation
-- 0x10 - KeyAgreement
-- Defaults to all flags (31): the common case, since fs/vault/external backends hand back plain,
-- exportable EC keys that support every usage. crypto.Migrate() corrects existing rows to 15
-- (everything except KeyAgreement) for nodes configured with the Azure Key Vault backend, whose EC
-- keys can only be used for signing.
alter table key_reference
    add column key_usage SMALLINT not null default 31;

-- +goose Down
alter table key_reference
    drop column key_usage;
