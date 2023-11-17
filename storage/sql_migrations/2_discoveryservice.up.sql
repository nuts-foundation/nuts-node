-- discoveryservices contains the known discovery services and the highest timestamp
create table discoveryservices
(
    id        text    not null primary key,
    timestamp integer not null
);

-- discoveryservice_presentations contains the presentations of the discovery services
create table discoveryservice_presentations
(
    id                      text    not null primary key,
    service_id              text    not null,
    timestamp               integer not null,
    credential_subject_id   text    not null,
    presentation_id         text    not null,
    presentation_raw        text    not null,
    presentation_expiration integer not null,
    unique (service_id, credential_subject_id),
    constraint fk_discovery_presentation_service_id foreign key (service_id) references discoveryservices (id) on delete cascade
);

-- discoveryservice_credentials is a credential in a presentation of the discovery service.
-- We could do without the table, but having it allows to have a normalized index for credential properties that appear on every credential.
-- Then we don't need rows in the properties table for them (having a column for those is faster than having a row in the properties table which needs to be joined).
create table discoveryservice_credentials
(
    id                    text not null primary key,
    presentation_id       text not null,
    credential_id         text not null,
    credential_issuer     text not null,
    credential_subject_id text not null,
    -- for now, credentials with at most 2 types are supported.
    -- The type stored in the type column will be the 'other' type, not being 'VerifiableCredential'.
    -- When credentials with 3 or more types appear, we could have to use a separate table for the types.
    credential_type       text,
    constraint fk_discoveryservice_credential_presentation foreign key (presentation_id) references discoveryservice_presentations (id) on delete cascade
);

-- discoveryservice_credential_props contains the credentialSubject properties of a credential in a presentation of the discovery service.
-- It is used by clients to search for presentations.
create table discoveryservice_credential_props
(
    id    text not null,
    key   text not null,
    value text,
    PRIMARY KEY (id, key),
    -- cascading delete: if the presentation gets deleted, the properties get deleted as well
    constraint fk_discoveryservice_credential_id foreign key (id) references discoveryservice_credentials (id) on delete cascade
);