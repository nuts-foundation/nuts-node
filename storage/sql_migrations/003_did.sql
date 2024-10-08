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
    created_at integer not null,
    updated_at integer not null,
    version int not null,
    raw $TEXT_TYPE not null,
    unique (did, version),
    foreign key (did) references did (id) on delete cascade
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

-- key_references store the private key information from the secure backend.
-- this is needed because verificationMethod IDs have specific requirements that the backend doesn't support.
create table key_reference
(
    -- kid is the key ID and matches the verification method ID
    kid varchar(415) primary key,
    -- key_name is the primary identifier for the key in the secure backend
    key_name varchar(255) not null,
    -- version is the version of the key in the secure backend, for backends that do not support key rotation, this is always "1"
    version varchar(255) not null
);

-- this table is used to store the verification methods for locally managed DIDs
create table did_verification_method
(
    -- id is the unique id of the verification method as it appears in the DID document using the fully qualified representation.
    id varchar(415) not null primary key,
    -- key_types is a base64 encoded bitmask of the key types supported by the verification method.
    -- 0x01 - AssertionMethod
    -- 0x02 - Authentication
    -- 0x04 - CapabilityDelegation
    -- 0x08 - CapabilityInvocation
    -- 0x10 - KeyAgreement
    key_types SMALLINT not null,
    -- weight is the weight of the verification method. The weight is used to determine the order of the verification methods.
    -- can also be derived from version of the backend storage.
    weight SMALLINT default 0,
    -- data is a JSON object containing the verification method data, e.g. the public key.
    -- When producing the verificationMethod, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE   not null
);

-- this table is used to link unique verification methods to all DID document versions they are used in
create table did_document_to_verification_method
(
    -- did_document_id references the DID document version
    did_document_id  varchar(36) not null,
    -- verification_method_id references the verification method
    verification_method_id  varchar(415) not null,
    primary key (did_document_id,verification_method_id),
    foreign key (did_document_id) references did_document_version (id) on delete cascade,
    foreign key (verification_method_id) references did_verification_method (id) on delete cascade
);

-- this table is used to store the services for locally managed DIDs
create table did_service
(
    -- id is the unique id of the service as it appears in the DID document using the shorthand representation.
    id   varchar(254) not null primary key,
    -- data is a JSON object containing the service data, e.g. the serviceEndpoint.
    -- When producing the service, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE   not null
);

-- this table is used to link unique services to all DID document versions they are used in
create table did_document_to_service
(
    -- did_document_id references the DID document version
    did_document_id  varchar(36) not null,
    -- service_id references the DID service
    service_id  varchar(254) not null,
    primary key (did_document_id,service_id),
    foreign key (did_document_id) references did_document_version (id) on delete cascade,
    foreign key (service_id) references did_service (id) on delete cascade
);

-- +goose Down
drop table did_document_to_verification_method;
drop table did_verification_method;
drop table did_document_to_service;
drop table did_service;
drop table did_change_log;
drop table did_document_version;
drop table did;
