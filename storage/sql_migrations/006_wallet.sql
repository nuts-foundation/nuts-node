-- +goose Up
create table wallet_credential
(
    credential_id varchar(415) not null,
    holder_did    varchar(370) not null,
    constraint fk_wallet_credential foreign key (credential_id) references credential (id)
);

create index idx_wallet_holder_did on wallet_credential (holder_did);

-- +goose Down
drop index idx_wallet_holder_did;
drop table wallet_credential;
