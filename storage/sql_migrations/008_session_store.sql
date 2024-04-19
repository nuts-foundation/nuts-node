-- migrate:up
create table session_store
(
    store   varchar(100) not null primary key,
    expires integer      not null,
    key     varchar(100) not null primary key,
    value   text         not null
);
create index idx_session_store_expires on session_store (expires);

-- migrate:down
drop table session_store;
