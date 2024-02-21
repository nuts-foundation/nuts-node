-- migrate:up
create table wallet_credential
(
    holder_did    varchar(500) not null,
    credential_id varchar(500) not null,
    primary key (holder_did, credential_id),
    constraint fk_wallet_credential foreign key (credential_id) references credential (id)
);

create index idx_wallet_holder_did on wallet_credential (holder_did);

-- migrate:down
drop index idx_wallet_holder_did;
drop table wallet_credential;
