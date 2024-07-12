-- +goose ENVSUB ON
-- +goose Up
-- this table is used to store locally managed DIDs
create table did
(
    -- id is the fully qualified DID
    id varchar(370) not null,
    subject varchar(370) not null,
    primary key (id)
);

create index did_subject_idx on did (subject);

create table did_document_version
(
    -- id is v4 uuid
    id varchar(36) not null primary key,
    did varchar(370) not null,
    created_at integer, -- make not nil in future PR
    updated_at integer, -- make not nil in future PR
    version int not null,
    raw $TEXT_TYPE, -- make not nil in future PR
    unique (did, version),
    foreign key (did) references did (id) on delete cascade,
    unique (did, version)
);

-- this table is used for the poor-mans 2-phase commit
create table did_change_log
(
    did_document_version_id varchar(36) not null primary key,
    transaction_id varchar(36) not null,
    type varchar(32) not null,
    foreign key (did_document_version_id) references did_document_version (id) on delete cascade
);

create index did_change_log_transaction_idx on did_change_log (transaction_id);

-- this table is used to store the verification methods for locally managed DIDs
create table did_verificationmethod
(
    -- id is the unique id of the verification method as it appears in the DID document using the shorthand representation.
    id varchar(254) not null primary key,
    -- did_document_id references the DID document version
    did_document_id  varchar(36) not null,
    -- key_types is a base64 encoded bitmask of the key types supported by the verification method.
    -- 0x01 - AssertionMethod
    -- 0x02 - Authentication
    -- 0x04 - CapabilityDelegation
    -- 0x08 - CapabilityInvocation
    -- 0x10 - KeyAgreement
    key_types SMALLINT not null,
    -- data is a JSON object containing the verification method data, e.g. the public key.
    -- When producing the verificationMethod, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE   not null,
    foreign key (did_document_id) references did_document_version (id) on delete cascade
);

-- this table is used to store the services for locally managed DIDs
create table did_service
(
    -- id is the unique id of the service as it appears in the DID document using the shorthand representation.
    id   varchar(254) not null primary key,
    -- did_document_id references the DID document version
    did_document_id  varchar(36) not null,
    -- data is a JSON object containing the service data, e.g. the serviceEndpoint.
    -- When producing the service, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE   not null,
    foreign key (did_document_id) references did_document_version (id) on delete cascade
);

-- +goose Down
drop table did_verificationmethod;
drop table did_service;
drop table did_change_log;
drop table did_document_version;
drop table did;
