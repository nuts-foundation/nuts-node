-- migrate:up
create table session_store
(
    store   varchar(100) not null,
    expires integer      not null,
    key     varchar(100) not null,
    value   text         not null,
    PRIMARY KEY (store, key)
);
create index idx_session_store_expires on session_store (expires);

-- migrate:down
drop table session_store;
