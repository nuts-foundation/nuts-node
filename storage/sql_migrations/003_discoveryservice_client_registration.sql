-- migrate:up
-- discovery_did_registration contains the DIDs that should be registered on the specified Discovery Service(s).
create table discovery_presentation_refresh
(
    -- service_id is the ID of the Discover Service that the DID should be registered on.
    -- It comes from the service definition.
    service_id   varchar(200) not null,
    -- did is the DID that should be registered on the Discovery Service.
    did          varchar(500) not null,
    -- next_refresh is the timestamp (seconds since Unix epoch) when the registration on the
    -- Discovery Service should be refreshed.
    next_refresh integer      not null,
    primary key (service_id, did),
    constraint fk_discovery_presentation_refresh_service foreign key (service_id) references discovery_service (id) on delete cascade
);
-- index for the next_registration column, used when checking which registrations need to be refreshed
create index idx_discovery_presentation_refresh on discovery_presentation_refresh (next_refresh);

-- migrate:down
drop table discovery_presentation_refresh;
