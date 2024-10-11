-- +goose Up
-- discovery_service: add seed column
alter table discovery_service add seed varchar(36);

-- +goose Down
alter table discovery_service drop column seed;
