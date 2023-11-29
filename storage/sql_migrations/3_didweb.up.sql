-- this table is used to store the did:web
create table vdr_didweb
(
    -- did is the fully qualified did:web
    did varchar(500) not null,
    primary key (did)
);

-- this table is used to store the services for a did:web
create table vdr_didweb_service
(
    -- id is the unique id of the service as it appears in the DID document.
    id               varchar(255)  not null,
    -- did references the containing did:web
    did              varchar(255)  not null,
    -- type is the service type
    type             varchar(255)  not null,
    -- service_endpoint is the service endpoint
    service_endpoint varchar(2000) not null,
    primary key (did, id),
    foreign key (did) references vdr_didweb (did) on delete cascade
);

-- this table is used to store the verification methods for a did:web
create table vdr_didweb_verificationmethod
(
    -- id is the unique id of the verification method as it appears in the DID document.
    id          varchar(255)  not null,
    -- did references the containing did:web
    did         varchar(255)  not null,
    -- type is the verification method type, e.g. "Ed25519VerificationKey2018" or "JsonWebKey2020"
    method_type varchar(255)  not null,
    -- data is a JSON object containing the verification method data, e.g. the public key.
    -- When producing the verificationMethod, data is used as JSON base object and the id and type are added.
    data        varchar(2000) not null,
    primary key (did, id),
    foreign key (did) references vdr_didweb (did) on delete cascade
);