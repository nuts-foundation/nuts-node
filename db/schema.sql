CREATE TABLE IF NOT EXISTS "schema_migrations" (version varchar(128) primary key);
CREATE TABLE discovery_service
(
    -- id is the unique identifier for the service. It comes from the service definition.
    id                varchar(200) not null primary key,
    lamport_timestamp integer      not null
);
CREATE TABLE discovery_presentation
(
    id                      varchar(36) not null primary key,
    service_id              varchar(36) not null,
    lamport_timestamp       integer     not null,
    credential_subject_id   varchar     not null,
    presentation_id         varchar     not null,
    presentation_raw        varchar     not null,
    presentation_expiration integer     not null,
    unique (service_id, credential_subject_id),
    constraint fk_discovery_presentation_service_id foreign key (service_id) references discovery_service (id) on delete cascade
);
CREATE INDEX idx_discovery_presentation_expiration on discovery_presentation (presentation_expiration);
CREATE TABLE discovery_credential
(
    id                    varchar(36) not null primary key,
    -- presentation_id is NOT the ID of the presentation (VerifiablePresentation.ID), but refers to the presentation record in the discovery_presentation table.
    presentation_id       varchar(36) not null,
    credential_id         varchar     not null,
    credential_issuer     varchar     not null,
    credential_subject_id varchar     not null,
    -- for now, credentials with at most 2 types are supported.
    -- The type stored in the type column will be the 'other' type, not being 'VerifiableCredential'.
    -- When credentials with 3 or more types appear, we could have to use a separate table for the types.
    credential_type       varchar,
    constraint fk_discovery_credential_presentation foreign key (presentation_id) references discovery_presentation (id) on delete cascade
);
CREATE TABLE discovery_credential_prop
(
    credential_id varchar(36) not null,
    key           varchar     not null,
    value         varchar,
    PRIMARY KEY (credential_id, key),
    -- cascading delete: if the presentation gets deleted, the properties get deleted as well
    constraint fk_discovery_credential_id foreign key (credential_id) references discovery_credential (id) on delete cascade
);
-- Dbmate schema migrations
INSERT INTO "schema_migrations" (version) VALUES
  ('001'),
  ('002');
