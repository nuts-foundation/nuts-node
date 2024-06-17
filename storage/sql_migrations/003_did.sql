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

create table did_document
(
    -- id is constructed as did + version
    id varchar(370) not null primary key,
    did  varchar(370) not null,
    version int not null,
    unique (did, version),
    foreign key (did) references did (id) on delete cascade
);

-- this table is used to store the verification methods for locally managed DIDs
create table did_verificationmethod
(
    -- id is the unique id of the verification method as it appears in the DID document using the shorthand representation.
    id   varchar(254) not null primary key,
    -- did_document_id references the DID document version
    did_document_id  varchar(370) not null,
    -- data is a JSON object containing the verification method data, e.g. the public key.
    -- When producing the verificationMethod, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE   not null,
    foreign key (did_document_id) references did_document (id) on delete cascade
);

-- this table is used to store the services for locally managed DIDs
create table did_service
(
    -- id is the unique id of the service as it appears in the DID document using the shorthand representation.
    id   varchar(254) not null primary key,
    -- did_document_id references the DID document version
    did_document_id  varchar(370) not null,
    -- data is a JSON object containing the service data, e.g. the serviceEndpoint.
    -- When producing the service, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE   not null,
    foreign key (did_document_id) references did_document (id) on delete cascade
);

-- +goose Down
drop table did;
drop table did_verificationmethod;
drop table did_service;