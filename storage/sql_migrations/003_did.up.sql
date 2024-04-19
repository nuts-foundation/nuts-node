-- migrate:up
-- this table is used to store locally managed DIDs
create table did
(
    -- did is the fully qualified DID
    did varchar(370) not null,
    primary key (did)
);

-- this table is used to store the verification methods for locally managed DIDs
create table did_verificationmethod
(
    -- id is the unique id of the verification method as it appears in the DID document.
    id   varchar(415) not null,
    -- did references the containing DID
    did  varchar(370) not null,
    -- data is a JSON object containing the verification method data, e.g. the public key.
    -- When producing the verificationMethod, data is used as JSON base object and the id and type are added.
    data text         not null,
    primary key (id),
    foreign key (did) references did (did) on delete cascade
);

-- this table is used to store the services for locally managed DIDs
create table did_service
(
    -- id is the unique id of the service as it appears in the DID document.
    id   varchar(415) not null,
    -- did references the containing DID
    did  varchar(370) not null,
    -- data is a JSON object containing the service data, e.g. the serviceEndpoint.
    -- When producing the service, data is used as JSON base object and the id and type are added.
    data text         not null,
    primary key (id),
    foreign key (did) references did (did) on delete cascade
);