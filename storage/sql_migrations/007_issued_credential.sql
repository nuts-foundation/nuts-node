-- +goose Up
create table issued_credential
(
    id varchar(415) not null primary key,
    constraint fk_issued_credential foreign key (id) references credential (id)
);

-- +goose Down
drop table issued_credential;
