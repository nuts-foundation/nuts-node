-- discovery contains the known discovery services and the highest timestamp
create table discovery_service
(
    id                varchar(36) not null primary key,
    lamport_timestamp integer     not null
);

-- discovery_presentation contains the presentations of the discovery services
create table discovery_presentation
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

-- discovery_credential is a credential in a presentation of the discovery service.
-- We could do without the table, but having it allows to have a normalized index for credential properties that appear on every credential.
-- Then we don't need rows in the properties table for them (having a column for those is faster than having a row in the properties table which needs to be joined).
create table discovery_credential
(
    id                    varchar(36) not null primary key,
    presentation_id       varchar(36) not null,
    credential_id         varchar     not null,
    credential_issuer     varchar     not null,
    credential_subject_id varchar     not null,
    -- for now, credentials with at most 2 types are supported.
    -- The type stored in the type column will be the 'other' type, not being 'VerifiableCredential'.
    -- When credentials with 3 or more types appear, we could have to use a separate table for the types.
    credential_type       varchar,
    constraint fk_discoveryservice_credential_presentation foreign key (presentation_id) references discovery_presentation (id) on delete cascade
);

-- discovery_credential_prop contains the credentialSubject properties of a credential in a presentation of the discovery service.
-- It is used by clients to search for presentations.
create table discovery_credential_prop
(
    credential_id varchar(36) not null,
    key           varchar     not null,
    value         varchar,
    PRIMARY KEY (credential_id, key),
    -- cascading delete: if the presentation gets deleted, the properties get deleted as well
    constraint fk_discoveryservice_credential_id foreign key (credential_id) references discovery_credential (id) on delete cascade
);