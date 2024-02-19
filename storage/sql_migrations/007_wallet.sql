-- migrate:up
create table wallet_credential
(
    holder_did    varchar(500) not null primary key,
    credential_id varchar(500) not null primary key,
    constraint fk_wallet_credential foreign key (credential_id) references credential (id)
);

-- migrate:down
drop table wallet_credential;
