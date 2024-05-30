-- +goose ENVSUB ON
-- +goose Up
create table session_store
(
    store   varchar(100) not null,
    expires integer      not null,
    key     varchar(100) not null,
    value   $TEXT_TYPE   not null,
    PRIMARY KEY (store, key)
);
create index idx_session_store_expires on session_store (expires);

-- +goose Down
drop table session_store;
