-- +goose Up
-- discovery_presentation: add validated column
alter table discovery_presentation add validated SMALLINT NOT NULL DEFAULT 0;

-- +goose Down
alter table discovery_presentation drop column validated;
