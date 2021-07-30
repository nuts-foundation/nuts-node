.PHONY: test run-generators update-docs

run-generators: gen-mocks gen-api gen-protobuf

install-tools:
	go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen
	go install github.com/golang/mock/mockgen
	go install google.golang.org/protobuf/cmd/protoc-gen-go
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc

gen-readme:
	./generate_readme.sh

gen-mocks:
	mockgen -destination=core/engine_mock.go -package=core -source=core/engine.go -imports echo=github.com/labstack/echo/v4
	mockgen -destination=core/echo_mock.go -package=core -source core/echo.go -imports echo=github.com/labstack/echo/v4
	mockgen -destination=crypto/mock.go -package=crypto -source=crypto/interface.go
	mockgen -destination=crypto/storage/mock.go -package=storage -source=crypto/storage/storage.go
	mockgen -destination=vdr/types/mock.go -package=types -source=vdr/types/interface.go -self_package github.com/nuts-foundation/nuts-node/vdr/types --imports did=github.com/nuts-foundation/go-did/did
	mockgen -destination=network/proto/mock.go -package=proto -source=network/proto/interface.go Protocol
	mockgen -destination=network/proto/senders_mock.go -package=proto -source=network/proto/senders.go messageSender
	mockgen -destination=network/p2p/mock.go -package=p2p -source=network/p2p/interface.go P2PNetwork
	mockgen -destination=network/p2p/connection_mock.go -package=p2p -source=network/p2p/connection.go grpcMessenger
	mockgen -destination=network/mock.go -package=network -source=network/interface.go
	mockgen -destination=network/dag/mock.go -package=dag -source=network/dag/interface.go DAG PayloadStore
	mockgen -destination=network/transport/network_grpc_mock.go -package=transport -source=network/transport/network_grpc.pb.go
	mockgen -destination=vcr/mock.go -package=vcr -source=vcr/interface.go
	mockgen -destination=vcr/concept/mock.go -package=concept -source=vcr/concept/registry.go Registry
	mockgen -destination=auth/mock.go -package=auth -source=auth/interface.go
	mockgen -destination=auth/services/mock.go -package=services -source=auth/services/services.go
	mockgen -destination=auth/contract/signer_mock.go -package=contract -source=auth/contract/signer.go
	mockgen -destination=didman/mock.go -package=didman -source=didman/types.go

gen-api:
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 docs/_static/crypto/v1.yaml | gofmt > crypto/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 -exclude-schemas DIDDocument,DIDDocumentMetadata,Service,VerificationMethod docs/_static/vdr/v1.yaml | gofmt > vdr/api/v1/generated.go
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 -exclude-schemas PeerDiagnostics docs/_static/network/v1.yaml | gofmt > network/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 -exclude-schemas VerifiableCredential,CredentialSubject,IssueVCRequest,Revocation docs/_static/vcr/v1.yaml | gofmt > vcr/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 docs/_static/auth/v1.yaml | gofmt > auth/api/v1/generated.go
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 -exclude-schemas ContactInformation,OrganizationSearchResult docs/_static/didman/v1.yaml | gofmt > didman/api/v1/generated.go

gen-protobuf:
	protoc --go_out=paths=source_relative:network -I network network/transport/network.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/network.proto

gen-docs:
	go run ./docs

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
