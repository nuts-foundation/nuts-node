.PHONY: test run-generators all-docs

run-generators: gen-mocks gen-api gen-protobuf

install-tools:
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
	go install go.uber.org/mock/mockgen@v0.4.0
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0

gen-mocks:
	mockgen -destination=auth/mock.go -package=auth -source=auth/interface.go
	mockgen -destination=auth/api/iam/jar_mock.go -package=iam -source=auth/api/iam/jar.go
	mockgen -destination=auth/contract/signer_mock.go -package=contract -source=auth/contract/signer.go
	mockgen -destination=auth/client/iam/mock.go -package=iam -source=auth/client/iam/interface.go
	mockgen -destination=auth/services/mock.go -package=services -source=auth/services/services.go
	mockgen -destination=auth/services/oauth/mock.go -package=oauth -source=auth/services/oauth/interface.go
	mockgen -destination=auth/services/selfsigned/types/mock.go -package=types -source=auth/services/selfsigned/types/types.go
	mockgen -destination=core/engine_mock.go -package=core -source=core/engine.go
	mockgen -destination=core/echo_mock.go -package=core -source=core/echo.go -imports echo=github.com/labstack/echo/v4
	mockgen -destination=crypto/mock.go -package=crypto -source=crypto/interface.go
	mockgen -destination=crypto/storage/spi/mock.go -package spi -source=crypto/storage/spi/interface.go
	mockgen -destination=crypto/storage/azure/mock.go -package azure -source=crypto/storage/azure/interface.go
	mockgen -destination=didman/mock.go -package=didman -source=didman/types.go
	mockgen -destination=discovery/mock.go -package=discovery -source=discovery/interface.go
	mockgen -destination=discovery/api/server/client/mock.go -package=client -source=discovery/api/server/client/interface.go
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
	mockgen -destination=pki/mock.go -package=pki -source=pki/interface.go
	mockgen -destination=policy/mock.go -package=policy -source=policy/interface.go
	mockgen -destination=storage/mock.go -package=storage -source=storage/interface.go
	mockgen -destination=vcr/types/mock.go -package=types -source=vcr/types/interface.go
	mockgen -destination=vcr/mock.go -package=vcr -source=vcr/interface.go
	mockgen -destination=vcr/holder/mock.go -package=holder -source=vcr/holder/interface.go
	mockgen -destination=vcr/issuer/mock.go -package=issuer -source=vcr/issuer/interface.go
	mockgen -destination=vcr/openid4vci/issuer_client_mock.go -package=openid4vci -source=vcr/openid4vci/issuer_client.go
	mockgen -destination=vcr/openid4vci/wallet_client_mock.go -package=openid4vci -source=vcr/openid4vci/wallet_client.go
	mockgen -destination=vcr/issuer/openid_mock.go -package=issuer -source=vcr/issuer/openid.go
	mockgen -destination=vcr/holder/openid_mock.go -package=holder -source=vcr/holder/openid.go
	mockgen -destination=vcr/openid4vci/identifiers_mock.go -package=openid4vci -source=vcr/openid4vci/identifiers.go
	mockgen -destination=vcr/signature/mock.go -package=signature -source=vcr/signature/signature.go
	mockgen -destination=vcr/verifier/mock.go -package=verifier -source=vcr/verifier/interface.go
	mockgen -destination=vdr/didnuts/ambassador_mock.go -package=didnuts -source=vdr/didnuts/ambassador.go
	mockgen -destination=vdr/didnuts/didstore/mock.go -package=didstore -source=vdr/didnuts/didstore/interface.go
	mockgen -destination=vdr/mock.go -package=vdr -source=vdr/interface.go
	mockgen -destination=vdr/resolver/did_mock.go -package=resolver -source=vdr/resolver/did.go
	mockgen -destination=vdr/resolver/service_mock.go -package=resolver -source=vdr/resolver/service.go
	mockgen -destination=vdr/resolver/key_mock.go -package=resolver -source=vdr/resolver/key.go
	mockgen -destination=vdr/resolver/finder_mock.go -package=resolver -source=vdr/resolver/finder.go
	mockgen -destination=vdr/didsubject/mock.go -package=didsubject -source=vdr/didsubject/interface.go


gen-api:
	oapi-codegen --config codegen/configs/common_ssi_types.yaml docs/_static/common/ssi_types.yaml | gofmt > api/generated.go
	oapi-codegen --config codegen/configs/crypto_v1.yaml -package v1 docs/_static/crypto/v1.yaml | gofmt > crypto/api/v1/generated.go
	oapi-codegen --config codegen/configs/vdr_v1.yaml docs/_static/vdr/v1.yaml | gofmt > vdr/api/v1/generated.go
	oapi-codegen --config codegen/configs/vdr_v2.yaml docs/_static/vdr/v2.yaml | gofmt > vdr/api/v2/generated.go
	oapi-codegen --config codegen/configs/network_v1.yaml docs/_static/network/v1.yaml | gofmt > network/api/v1/generated.go
	oapi-codegen --config codegen/configs/vcr_v2.yaml docs/_static/vcr/vcr_v2.yaml | gofmt > vcr/api/vcr/v2/generated.go
	oapi-codegen --config codegen/configs/vcr_openid4vci_v0.yaml docs/_static/vcr/openid4vci_v0.yaml | gofmt > vcr/api/openid4vci/v0/generated.go
	oapi-codegen --config codegen/configs/auth_v1.yaml docs/_static/auth/v1.yaml | gofmt > auth/api/auth/v1/generated.go
	oapi-codegen --config codegen/configs/auth_client_v1.yaml docs/_static/auth/v1.yaml | gofmt > auth/api/auth/v1/client/generated.go
	oapi-codegen --config codegen/configs/auth_employeeid.yaml auth/services/selfsigned/web/spec.yaml | gofmt > auth/services/selfsigned/web/generated.go
	oapi-codegen --config codegen/configs/didman_v1.yaml docs/_static/didman/v1.yaml | gofmt > didman/api/v1/generated.go
	oapi-codegen --config codegen/configs/discovery_v1.yaml docs/_static/discovery/v1.yaml | gofmt > discovery/api/v1/generated.go
	oapi-codegen --config codegen/configs/discovery_server.yaml docs/_static/discovery/server.yaml | gofmt > discovery/api/server/generated.go
	oapi-codegen --config codegen/configs/crypto_store_client.yaml https://raw.githubusercontent.com/nuts-foundation/secret-store-api/main/nuts-storage-api-v1.yaml | gofmt > crypto/storage/external/generated.go

	# IAM is a special case, needs merging of the "integrator's" OAS with the OAuth2/OpenID4VCI/OpenID4VP spec
	go run ./codegen/oas-merge/main.go docs/_static/auth/v2.yaml docs/_static/auth/iam.partial.yaml 2> docs/_static/auth/v2-iam-combined.tmp.yaml
	oapi-codegen --config codegen/configs/auth_v2.yaml docs/_static/auth/v2-iam-combined.tmp.yaml | gofmt > auth/api/iam/generated.go
	oapi-codegen -generate client,types --config codegen/configs/auth_v2.yaml docs/_static/auth/v2.yaml | gofmt > e2e-tests/browser/client/iam/generated.go

gen-protobuf:
	protoc --go_out=paths=source_relative:network -I network network/transport/v2/protocol.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/v2/protocol.proto
	protoc --go_out=paths=source_relative:network -I network network/transport/grpc/testprotocol.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/grpc/testprotocol.proto

DIR ?= "$(shell pwd)"
gen-diagrams:
	rm ${DIR}/docs/_static/images/diagrams/*.svg
	docker run -v ${DIR}/docs/diagrams:/data rlespinasse/drawio-export -f svg
	mv ${DIR}/docs/diagrams/export/* ${DIR}/docs/_static/images/diagrams/

# requires python package rst-include. install using `pip install rst-include`
cli-docs:
	go run ./docs docs
	rst_include include README_template.rst README.rst

all-docs: cli-docs gen-diagrams

fix-copyright:
	go run ./docs copyright

lint:
	golangci-lint run -v

test:
	go test ./...

e2e-test:
	docker build . --tag nutsfoundation/nuts-node:e2e
	cd e2e-tests && IMAGE_NODE_A=nutsfoundation/nuts-node:e2e IMAGE_NODE_B=nutsfoundation/nuts-node:e2e ./run-tests.sh

OUTPUT ?= "$(shell pwd)/nuts"
GIT_COMMIT ?= "$(shell git rev-list -1 HEAD)"
GIT_BRANCH ?= "$(shell git symbolic-ref --short HEAD)"
GIT_VERSION ?= "$(shell git name-rev --tags --name-only $(shell git rev-parse HEAD))"
build:
	go build -tags jwx_es256k -ldflags="-w -s -X 'github.com/nuts-foundation/nuts-node/core.GitCommit=${GIT_COMMIT}' -X 'github.com/nuts-foundation/nuts-node/core.GitBranch=${GIT_BRANCH}' -X 'github.com/nuts-foundation/nuts-node/core.GitVersion=${GIT_VERSION}'" -o ${OUTPUT}

docker:
	docker build --build-arg GIT_COMMIT=${GIT_COMMIT} --build-arg GIT_BRANCH=${GIT_BRANCH} --build-arg GIT_VERSION=${GIT_VERSION} -t nutsfoundation/nuts-node:master .

docker-dev: docker
	docker build -t nutsfoundation/nuts-node:dev development/dev-image

