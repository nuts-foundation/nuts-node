-- +goose ENVSUB ON
-- +goose Up
-- this table is used to store tenants of the local node. Tenants hold 1 or more DIDs.
create table tenant
(
    id      varchar(40) primary key,
    created timestamp not null default current_timestamp
);

create table tenant_did (
    tenant_id varchar(40) not null,
    did       varchar(370) not null,
    primary key (tenant_id, did),
    foreign key (tenant_id) references tenant (id) on delete cascade,
);
-- this table is used to store the verification methods for locally managed DIDs
create table tenant_verificationmethod
(
    id  varchar(40) not null,
    tenant_id varchar(40) not null,
    -- data is a JSON object containing the verification method data, e.g. the public key.
    -- When producing the verificationMethod, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE not null,
    primary key (id),
    foreign key (did) references did (did) on delete cascade
);

-- this table is used to store the services for locally managed DIDs
create table did_service
(
    -- id is the unique id of the service as it appears in the DID document.
    id  varchar(415) not null,
    -- did references the containing DID
    did varchar(370) not null,
    -- data is a JSON object containing the service data, e.g. the serviceEndpoint.
    -- When producing the service, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE not null,
    primary key (id),
    foreign key (did) references did (did) on delete cascade
);

-- +goose Down
drop table did;
drop table did_verificationmethod;
drop table did_service;