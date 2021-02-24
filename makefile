.PHONY: test run-generators update-docs

run-generators: gen-readme gen-mocks gen-api gen-protobuf

install-tools:
	export GO111MODULE=on  # default in Go >= 1.16
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
	mockgen -destination=vdr/types/mock.go -package=types -source=vdr/types/interface.go -self_package github.com/nuts-foundation/nuts-node/vdr/types --imports did=github.com/nuts-foundation/go-did
	mockgen -destination=network/proto/mock.go -package=proto -source=network/proto/interface.go Protocol
	mockgen -destination=network/p2p/mock.go -package=p2p -source=network/p2p/interface.go P2PNetwork
	mockgen -destination=network/mock.go -package=network -source=network/interface.go
	mockgen -destination=network/dag/mock.go -package=dag -source=network/dag/interface.go DAG PayloadStore

gen-api:
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 docs/_static/crypto/v1.yaml > crypto/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -templates codegen/oapi/ -package v1 -exclude-schemas DIDDocument,DIDDocumentMetadata,Service,VerificationMethod docs/_static/vdr/v1.yaml > vdr/api/v1/generated.go
	oapi-codegen -generate types,server,client -templates codegen/oapi/ -package v1 docs/_static/network/v1.yaml > network/api/v1/generated.go

gen-protobuf:
	protoc --go_out=paths=source_relative:network -I network network/transport/network.proto
	protoc --go-grpc_out=require_unimplemented_servers=false,paths=source_relative:network -I network network/transport/network.proto

gen-docs:
	go run ./docs

test:
	go test ./...

update-docs: gen-docs gen-readme
