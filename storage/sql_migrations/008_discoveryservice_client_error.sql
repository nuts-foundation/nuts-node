-- +goose ENVSUB ON
-- +goose Up
-- discovery_presentation_error contains errors for activated registrations that once succeeded but fail to refresh.
create table discovery_presentation_error
(
    -- service_id is the ID of the Discover Service that the DID should be registered on.
    -- It comes from the service definition.
    service_id   varchar(200) not null,
    -- subject_id is the subject that should be registered on the Discovery Service.
    subject_id   varchar(370) not null,
    -- reason contains the error message that caused the registration to fail.
    error $TEXT_TYPE,
    -- last_occurrence is the timestamp (seconds since Unix epoch) when the registration last failed.
    last_occurrence integer      not null,
    primary key (service_id, subject_id),
    constraint fk_discovery_presentation_refresh_service foreign key (service_id) references discovery_service (id) on delete cascade
);

-- +goose Down
drop table discovery_presentation_error;
