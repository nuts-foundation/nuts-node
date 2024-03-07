-- migrate:up
-- this table is used to store the did:web
create table did
(
    -- did is the fully qualified did:web
    did varchar(370) not null,
    primary key (did)
);

-- this table is used to store the verification methods for a did:web
create table did_verificationmethod
(
    -- id is the unique id of the verification method as it appears in the DID document.
    id   varchar(415) not null,
    -- did references the containing did:web
    did  varchar(370) not null,
    -- data is a JSON object containing the verification method data, e.g. the public key.
    -- When producing the verificationMethod, data is used as JSON base object and the id and type are added.
    data text         not null,
    primary key (did, id),
    foreign key (did) references did (did) on delete cascade
);

-- migrate:down
drop table did;
drop table did_verificationmethod;