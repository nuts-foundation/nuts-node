-- +goose ENVSUB ON
-- +goose Up
create table credential
(
    id         varchar(415) not null primary key,
    issuer     varchar(370) not null,
    subject_id varchar(370) not null,
    raw        $TEXT_TYPE   not null,
    -- for now, credentials with at most 2 types are supported.
    -- The type stored in the type column will be the 'other' type, not being 'VerifiableCredential'.
    -- When credentials with 3 or more types appear, we could have to use a separate table for the types.
    type       varchar(100)
);

-- credential_prop contains the credentialSubject properties of a credential.
-- It is to search for credentials.
create table credential_prop
(
    credential_id varchar(415) not null,
    path          varchar(100) not null,
    value         varchar(500),
    PRIMARY KEY (credential_id, path),
    -- cascading delete: if the presentation gets deleted, the properties get deleted as well
    constraint fk_discovery_credential_id foreign key (credential_id) references credential (id) on delete cascade
);

-- +goose Down
drop table credential;
drop table credential_prop;
