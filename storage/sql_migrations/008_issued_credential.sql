-- migrate:up
create table issued_credential
(
    id varchar(500) not null primary key,
    constraint fk_issued_credential foreign key (id) references credential (id)
);

-- migrate:down
drop table issued_credential;
