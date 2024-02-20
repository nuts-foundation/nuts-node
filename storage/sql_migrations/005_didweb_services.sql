-- migrate:up
-- this table is used to store the services for a did:web
create table vdr_didweb_service
(
    -- id is the unique id of the service as it appears in the DID document.
    id   varchar(500) not null,
    -- did references the containing did:web
    did  varchar(255) not null,
    -- data is a JSON object containing the service data, e.g. the serviceEndpoint.
    -- When producing the service, data is used as JSON base object and the id and type are added.
    data text         not null,
    primary key (did, id),
    foreign key (did) references vdr_didweb (did) on delete cascade
);

-- migrate:down
drop table vdr_didweb_service;