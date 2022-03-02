.PHONY: test run-generators update-docs

run-generators: gen-mocks gen-api gen-protobuf

install-tools:
	go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.9.1
	go install github.com/golang/mock/mockgen@v1.6.0
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0

gen-readme:
	./generate_readme.sh

gen-mocks:
	mockgen -destination=core/engine_mock.go -package=core -source=core/engine.go -imports echo=github.com/labstack/echo/v4
	mockgen -destination=core/echo_mock.go -package=core -source core/echo.go -imports echo=github.com/labstack/echo/v4
	mockgen -destination=crypto/mock.go -package=crypto -source=crypto/interface.go
	mockgen -destination=crypto/storage/mock.go -package=storage -source=crypto/storage/storage.go
	mockgen -destination=vdr/types/mock.go -package=types -source=vdr/types/interface.go -self_package github.com/nuts-foundation/nuts-node/vdr/types --imports did=github.com/nuts-foundation/go-did/did
	mockgen -destination=vdr/doc/resolvers_mock.go -package=doc -source=vdr/doc/resolvers.go
	mockgen -destination=network/mock.go -package=network -source=network/interface.go
	mockgen -destination=network/transport/connection_manager_mock.go -package=transport -source=network/transport/connection_manager.go
	mockgen -destination=network/transport/protocol_mock.go -package=transport -source=network/transport/protocol.go Protocol
	mockgen -destination=network/transport/grpc/authenticator_mock.go -package=grpc -source=network/transport/grpc/authenticator.go
	mockgen -destination=network/transport/grpc/connection_list_mock.go -package=grpc -source=network/transport/grpc/connection_list.go
	mockgen -destination=network/transport/grpc/connection_mock.go -package=grpc -source=network/transport/grpc/connection.go
	mockgen -destination=network/transport/grpc/interface_mock.go -package=grpc -source=network/transport/grpc/interface.go
	mockgen -destination=network/transport/v1/logic/mock.go -package=logic -source=network/transport/v1/logic/interface.go Protocol
	mockgen -destination=network/transport/v1/logic/senders_mock.go -package=logic -source=network/transport/v1/logic/senders.go
	mockgen -destination=network/transport/v1/logic/payload_collector_mock.go -package=logic -source=network/transport/v1/logic/payload_collector.go
	mockgen -destination=network/transport/v1/protobuf/network_grpc_mock.go -package=protobuf -source=network/transport/v1/protobuf/network_grpc.pb.go
	mockgen -destination=network/transport/v2/protocol_grpc_mock.pb.go -package=v2 -source=network/transport/v2/protocol_grpc.pb.go
	mockgen -destination=network/transport/v2/scheduler_mock.go -package=v2 -source=network/transport/v2/scheduler.go
	mockgen -destination=network/transport/v2/gossip/mock.go -package=gossip -source=network/transport/v2/gossip/manager.go
	mockgen -destination=network/dag/mock.go -package=dag -source=network/dag/interface.go State
	mockgen -destination=vcr/types_mock.go -package=vcr -source=vcr/types/interface.go
	mockgen -destination=vcr/mock.go -package=vcr -source=vcr/vcr.go
	mockgen -destination=vcr/issuer/mock.go -package=issuer -source=vcr/issuer/interface.go
	mockgen -destination=vcr/verifier/mock.go -package=verifier -source=vcr/verifier/interface.go
	mockgen -destination=vcr/concept/mock.go -package=concept -source=vcr/concept/registry.go Registry
	mockgen -destination=vcr/signature/mock.go -package=signature -source=vcr/signature/signature.go
	mockgen -destination=auth/mock.go -package=auth -source=auth/interface.go
	mockgen -destination=auth/services/mock.go -package=services -source=auth/services/services.go
	mockgen -destination=auth/contract/signer_mock.go -package=contract -source=auth/contract/signer.go
	mockgen -destination=didman/mock.go -package=didman -source=didman/types.go
	mockgen -destination=crl/mock.go -package crl -source=crl/validator.go Validator
	mockgen -destination=events/events_mock.go -package events -source=events/interface.go Event
	mockgen -destination=events/mock.go -package events -source=events/conn.go Conn ConnectionPool

gen-api:
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 docs/_static/crypto/v1.yaml | gofmt > crypto/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 -exclude-schemas DIDDocument,DIDDocumentMetadata,Service,VerificationMethod docs/_static/vdr/v1.yaml | gofmt > vdr/api/v1/generated.go
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 -exclude-schemas PeerDiagnostics docs/_static/network/v1.yaml | gofmt > network/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 -exclude-schemas VerifiableCredential,CredentialSubject,IssueVCRequest,Revocation docs/_static/vcr/v1.yaml | gofmt > vcr/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v2 -exclude-schemas VerifiableCredential,CredentialSubject,Revocation docs/_static/vcr/v2.yaml | gofmt > vcr/api/v2/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 -exclude-schemas VerifiableCredential,VerifiablePresentation docs/_static/auth/v1.yaml | gofmt > auth/api/v1/generated.go
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 -exclude-schemas ContactInformation,OrganizationSearchResult docs/_static/didman/v1.yaml | gofmt > didman/api/v1/generated.go

gen-protobuf:
	protoc --go_out=paths=source_relative:network -I network network/transport/v1/protobuf/network.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/v1/protobuf/network.proto
	protoc --go_out=paths=source_relative:network -I network network/transport/v2/protocol.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/v2/protocol.proto
	protoc --go_out=paths=source_relative:network -I network network/transport/grpc/testprotocol.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/grpc/testprotocol.proto

gen-docs:
	go run ./docs docs

fix-copyright:
	go run ./docs copyright

test:
	go test ./...

update-docs: gen-docs gen-readme

OUTPUT ?= "$(shell pwd)/nuts"
GIT_COMMIT ?= "$(shell git rev-list -1 HEAD)"
GIT_BRANCH ?= "$(shell git symbolic-ref --short HEAD)"
GIT_VERSION ?= "$(shell git name-rev --tags --name-only $(shell git rev-parse HEAD))"
build:
	go build -ldflags="-w -s -X 'github.com/nuts-foundation/nuts-node/core.GitCommit=${GIT_COMMIT}' -X 'github.com/nuts-foundation/nuts-node/core.GitBranch=${GIT_BRANCH}' -X 'github.com/nuts-foundation/nuts-node/core.GitVersion=${GIT_VERSION}'" -o ${OUTPUT}

docker:
	docker build --build-arg GIT_COMMIT=${GIT_COMMIT} --build-arg GIT_BRANCH=${GIT_BRANCH} --build-arg GIT_VERSION=${GIT_VERSION} -t nutsfoundation/nuts-node:latest .
