-- +goose ENVSUB ON
-- +goose Up
-- discovery contains the known discovery services and the associated tags.
create table discovery_service
(
    -- id is the unique identifier for the service. It comes from the service definition.
    id         varchar(36) not null primary key,
    -- tag is the latest tag pointing to the last presentation registered on the service.
    last_tag   varchar(40)  null,
    -- tag_prefix is used to prefix the tag of the presentations of the service.
    -- It is only populated if the node is server for this service.
    tag_prefix varchar(5)   null
);

-- discovery_presentation contains the presentations of the discovery services
create table discovery_presentation
(
    id                      varchar(36)  not null primary key,
    service_id              varchar(36)  not null,
    -- lamport_timestamp is the lamport clock of the presentation, converted to a tag and then returned to the client.
    -- It is only populated if the node is server for this service.
    lamport_timestamp       integer      null,
    credential_subject_id   varchar(370) not null,
    presentation_id         varchar(415) not null,
    presentation_raw        $TEXT_TYPE         not null,
    presentation_expiration integer      not null,
    unique (service_id, credential_subject_id),
    constraint fk_discovery_presentation_service_id foreign key (service_id) references discovery_service (id) on delete cascade
);
-- index for the presentation_expiration column, used by prune()
create index idx_discovery_presentation_expiration on discovery_presentation (presentation_expiration);

-- discovery_credential is a credential in a presentation of the discovery service.
-- We could do without the table, but having it allows to have a normalized index for credential properties that appear on every credential.
-- Then we don't need rows in the properties table for them (having a column for those is faster than having a row in the properties table which needs to be joined).
create table discovery_credential
(
    id                    varchar(36)  not null primary key,
    -- presentation_id is NOT the ID of the presentation (VerifiablePresentation.ID), but refers to the presentation record in the discovery_presentation table.
    presentation_id       varchar(36)  not null,
    credential_id         varchar(415) not null,
    constraint fk_discovery_credential_presentation foreign key (presentation_id) references discovery_presentation (id) on delete cascade,
    constraint fk_discovery_credential foreign key (credential_id) references credential (id)
);

-- +goose Down
drop table discovery_service;
drop table discovery_presentation;
drop table discovery_credential;
