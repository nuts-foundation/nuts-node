-- +goose ENVSUB ON
-- +goose Up
-- this table is used to store tenants of the local node. Tenants hold 1 or more DIDs.
create table tenant
(
    id         varchar(40) primary key,
    -- created_at is the seconds since Unix Epoch when this tenant was created
    created_at integer not null
);

create table tenant_did (
    tenant_id   varchar(40) not null,
    did         varchar(370) not null,
    primary key (tenant_id, did),
    foreign key (tenant_id) references tenant (id) on delete cascade
);

-- this table is used to store the verification methods for locally managed DIDs
create table tenant_verificationmethod
(
    tenant_id varchar(40) not null,
    -- method_id is unique within the tenant. It will typically appear as verification method ID fragment in the DID documents.
    method_id varchar(80) not null,
    -- data is a JSON object containing the verification method data, e.g. the public key.
    -- When producing the verificationMethod, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE not null,
    primary key (tenant_id, method_id),
    foreign key (tenant_id) references tenant (id) on delete cascade
);
create index idx_tenant_verificationmethod_tenant on tenant_verificationmethod (tenant_id);

-- this table is used to store the services for tenants
create table tenant_service
(
    tenant_id varchar(40) not null,
    -- service_id is unique within the tenant. It will typically appear as service ID fragment in the DID documents.
    service_id  varchar(80) not null,
    -- data is a JSON object containing the service data, e.g. the serviceEndpoint.
    -- When producing the service, data is used as JSON base object and the id and type are added.
    data $TEXT_TYPE not null,
    primary key (tenant_id, service_id),
    foreign key (tenant_id) references tenant (id) on delete cascade
);
create index idx_tenant_service_tenant on tenant_service (tenant_id);

-- +goose Down
drop table tenant;
drop table tenant_did;
drop index idx_tenant_verificationmethod_tenant;
drop table tenant_verificationmethod;
drop index idx_tenant_service_tenant;
drop table tenant_service;