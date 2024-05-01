-- +goose ENVSUB ON
-- +goose Up
-- status_list_credential: latest version of known credentials.
create table status_list_credential
(
    -- id: VC.credentialSubject.ID; URL where this status list credential can be downloaded.
    -- the credential served at this URL may change over time, so we only keep the latest
    subject_id      varchar(500)    not null    primary key,
    -- StatusPurpose is the purpose listed in the StatusList2021Credential.credentialSubject
    status_purpose  varchar(25)     not null,
    -- expanded StatusList2021 bitstring
    expanded        $TEXT_TYPE            not null,
    -- created is the seconds since Unix Epoch when this credentialRecord was generated
    created_at      integer         not null,
    -- expires is the seconds since Unix Epoch when the credential expires, only present if set.
    expires         integer         null,
    -- raw credential, either base64 (jwt) or json.
    raw             $TEXT_TYPE            not null
);

-- status_list: keeps track of all status list credentials issued by an issuer, and the highest status list index issued for each credential.
create table status_list
(
    -- subject_id: VC.credentialSubject.ID; URL where this status list credential can be downloaded.
    subject_id          varchar(500)    not null    primary key,
    -- issuer: the DID of the issuer of this statusListCredential.
    issuer              varchar(370)    not null,
    -- page: the n-th StatusList2021Credential issued by this issuer.
    --      Used to find the credential statusList2021Entries are being issued to. Could require an index in the future.
    page                integer         not null,
    -- last_issued_index: the highest status_list_index issued for this page. Should not be incremented above the max statusListIndex.
    last_issued_index   integer         not null,
    -- Ties status list credentials to DID management.
    constraint fk_issuer_did foreign key (issuer) references did (did) on delete cascade
);

-- status_list_entry: lists all status list entries for which the status bit is set to true. (revocation table)
create table status_list_entry
(
    -- status_list_credential: URL where the status list credential can be resolved; as referenced in the status list entry.
    status_list_credential  varchar(500)    not null,
    -- status_list_index: index in the status list bitstring; as referenced in the status list entry.
    status_list_index       integer         not null,
    -- credential_id: id of the credential that lists this status.
    --      Could be present more than once if the credential's credentialStatus contains multiple status list entries.
    credential_id           varchar(415)    not null,
    -- created_at: timestamp the status was registered (status bit set). Measured in seconds since UNIX epoch.
    created_at              integer         not null,
    -- status_list_entry_id: unique identifier of a status list entry
    constraint status_list_entry_id primary key (status_list_credential, status_list_index),
    -- Ties the status_list_credential to an issuer (did) via the status_list_issuer table
    constraint fk_status_list_credential foreign key (status_list_credential) references status_list (subject_id) on delete cascade
);

-- +goose Down
drop table status_list_credential;
drop table status_list;
drop table status_list_entry;
