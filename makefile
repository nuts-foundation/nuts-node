.PHONY: test run-generators update-docs

run-generators: gen-mocks gen-api gen-protobuf

install-tools:
	go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.12.4
	go install github.com/golang/mock/mockgen@v1.6.0
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30.0
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

gen-readme:
	./generate_readme.sh

gen-mocks:
	mockgen -destination=auth/contract/signer_mock.go -package=contract -source=auth/contract/signer.go
	mockgen -destination=auth/services/mock.go -package=services -source=auth/services/services.go
	mockgen -destination=auth/services/oauth/mock.go -package=oauth -source=auth/services/oauth/interface.go
	mockgen -destination=core/engine_mock.go -package=core -source=core/engine.go
	mockgen -destination=core/echo_mock.go -package=core -source=core/echo.go -imports echo=github.com/labstack/echo/v4
	mockgen -destination=crl/mock.go -package=crl -source=crl/validator.go Validator
	mockgen -destination=crypto/mock.go -package=crypto -source=crypto/interface.go
	mockgen -destination=crypto/storage/spi/mock.go -package spi -source=crypto/storage/spi/interface.go
	mockgen -destination=didman/mock.go -package=didman -source=didman/types.go
	mockgen -destination=events/events_mock.go -package=events -source=events/interface.go Event
	mockgen -destination=events/mock.go -package=events -source=events/conn.go Conn ConnectionPool
	mockgen -destination=http/echo_mock.go -package=http -source=http/echo.go -imports echo=github.com/labstack/echo/v4
	mockgen -destination=network/mock.go -package=network -source=network/interface.go
	mockgen -destination=network/dag/mock.go -package=dag -source=network/dag/interface.go State
	mockgen -destination=network/dag/notifier_mock.go -package=dag -source=network/dag/notifier.go Notifier
	mockgen -destination=network/transport/connection_manager_mock.go -package=transport -source=network/transport/connection_manager.go
	mockgen -destination=network/transport/protocol_mock.go -package=transport -source=network/transport/protocol.go Protocol
	mockgen -destination=network/transport/grpc/authenticator_mock.go -package=grpc -source=network/transport/grpc/authenticator.go
	mockgen -destination=network/transport/grpc/connection_list_mock.go -package=grpc -source=network/transport/grpc/connection_list.go
	mockgen -destination=network/transport/grpc/connection_mock.go -package=grpc -source=network/transport/grpc/connection.go
	mockgen -destination=network/transport/grpc/interface_mock.go -package=grpc -source=network/transport/grpc/interface.go
	mockgen -destination=network/transport/v2/senders_mock.go -package=v2 -source=network/transport/v2/senders.go
	mockgen -destination=network/transport/v2/gossip/mock.go -package=gossip -source=network/transport/v2/gossip/manager.go
	mockgen -destination=storage/mock.go -package=storage -source=storage/interface.go
	mockgen -destination=vcr/mock.go -package=vcr -source=vcr/interface.go
	mockgen -destination=vcr/holder/mock.go -package=holder -source=vcr/holder/interface.go
	mockgen -destination=vcr/issuer/mock.go -package=issuer -source=vcr/issuer/interface.go
	mockgen -destination=vcr/signature/mock.go -package=signature -source=vcr/signature/signature.go
	mockgen -destination=vcr/verifier/mock.go -package=verifier -source=vcr/verifier/interface.go
	mockgen -destination=vdr/ambassador_mock.go -package=vdr -source=vdr/ambassador.go
	mockgen -destination=vdr/didstore/mock.go -package=didstore -source=vdr/didstore/interface.go
	mockgen -destination=vdr/didservice/resolvers_mock.go -package=didservice -source=vdr/didservice/resolvers.go
	mockgen -destination=vdr/types/mock.go -package=types -source=vdr/types/interface.go -self_package github.com/nuts-foundation/nuts-node/vdr/types --imports did=github.com/nuts-foundation/go-did/did
	mockgen -destination=auth/services/selfsigned/types/mock.go -package=types -source=auth/services/selfsigned/types/types.go

gen-api:
	oapi-codegen --config codegen/configs/common_ssi_types.yaml docs/_static/common/ssi_types.yaml | gofmt > api/ssi_types.go
	oapi-codegen --config codegen/configs/crypto_v1.yaml -package v1 docs/_static/crypto/v1.yaml | gofmt > crypto/api/v1/generated.go
	oapi-codegen --config codegen/configs/vdr_v1.yaml docs/_static/vdr/v1.yaml | gofmt > vdr/api/v1/generated.go
	oapi-codegen --config codegen/configs/network_v1.yaml docs/_static/network/v1.yaml | gofmt > network/api/v1/generated.go
	oapi-codegen --config codegen/configs/vcr_v2.yaml docs/_static/vcr/v2.yaml | gofmt > vcr/api/v2/generated.go
	oapi-codegen --config codegen/configs/auth_v1.yaml docs/_static/auth/v1.yaml | gofmt > auth/api/auth_v1/generated.go
	oapi-codegen --config codegen/configs/auth_client_v1.yaml docs/_static/auth/v1.yaml | gofmt > auth/api/auth_v1/client/generated.go
	oapi-codegen --config codegen/configs/auth_employeeid.yaml auth/services/selfsigned/web/spec.yaml | gofmt > auth/services/selfsigned/web/generated.go
	oapi-codegen --config codegen/configs/didman_v1.yaml docs/_static/didman/v1.yaml | gofmt > didman/api/v1/generated.go
	oapi-codegen --config codegen/configs/crypto_store_client.yaml https://raw.githubusercontent.com/nuts-foundation/secret-store-api/main/nuts-storage-api-v1.yaml | gofmt > crypto/storage/external/generated.go

gen-protobuf:
	protoc --go_out=paths=source_relative:network -I network network/transport/v2/protocol.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/v2/protocol.proto
	protoc --go_out=paths=source_relative:network -I network network/transport/grpc/testprotocol.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/grpc/testprotocol.proto

gen-docs:
	go run ./docs docs

DIR ?= "$(shell pwd)"
gen-diagrams:
	rm ${DIR}/docs/_static/images/diagrams/*.svg
	docker run -v ${DIR}/docs/diagrams:/data rlespinasse/drawio-export -f svg
	mv ${DIR}/docs/diagrams/export/* ${DIR}/docs/_static/images/diagrams/

fix-copyright:
	go run ./docs copyright

test:
	go test ./...

update-docs: gen-docs gen-readme gen-diagrams

OUTPUT ?= "$(shell pwd)/nuts"
GIT_COMMIT ?= "$(shell git rev-list -1 HEAD)"
GIT_BRANCH ?= "$(shell git symbolic-ref --short HEAD)"
GIT_VERSION ?= "$(shell git name-rev --tags --name-only $(shell git rev-parse HEAD))"
build:
	go build -ldflags="-w -s -X 'github.com/nuts-foundation/nuts-node/core.GitCommit=${GIT_COMMIT}' -X 'github.com/nuts-foundation/nuts-node/core.GitBranch=${GIT_BRANCH}' -X 'github.com/nuts-foundation/nuts-node/core.GitVersion=${GIT_VERSION}'" -o ${OUTPUT}

docker:
	docker build --build-arg GIT_COMMIT=${GIT_COMMIT} --build-arg GIT_BRANCH=${GIT_BRANCH} --build-arg GIT_VERSION=${GIT_VERSION} -t nutsfoundation/nuts-node:latest .
