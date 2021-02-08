.PHONY: test run-generators update-docs

run-generators: gen-readme gen-mocks gen-api gen-protobuf

gen-readme:
	./generate_readme.sh

gen-mocks:
	mockgen -destination=core/mock.go -package=core -source=core/engine.go -imports echo=github.com/labstack/echo/v4
	mockgen -destination=crypto/types/mock.go -package=types -source=crypto/types/interface.go
	mockgen -destination=vdr/types/mock.go -package=types -source=vdr/types/interface.go -self_package github.com/nuts-foundation/nuts-node/vdr/types --imports did=github.com/nuts-foundation/go-did
	mockgen -destination=network/proto/mock.go -package=proto -source=network/proto/interface.go Protocol
	mockgen -destination=network/p2p/mock.go -package=p2p -source=network/p2p/interface.go P2PNetwork
	mockgen -destination=network/types/mock.go -package=types -source=network/types/interface.go
	mockgen -destination=network/dag/mock.go -package=dag -source=network/dag/interface.go DAG PayloadStore

gen-api:
	oapi-codegen -generate types,server,client -package v1 docs/_static/crypto/v1.yaml > crypto/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -package v1 -exclude-schemas DIDDocument,DIDDocumentMetadata,Service,VerificationMethod docs/_static/vdr/v1.yaml > vdr/api/v1/generated.go
	oapi-codegen -generate types,server,client -package v1 docs/_static/network/v1.yaml > network/api/v1/generated.go

gen-protobuf:
	protoc -I network network/transport/network.proto --go_out=plugins=grpc,paths=source_relative:network

gen-docs:
	go run ./docs

test:
	go test ./...

update-docs: gen-docs gen-readme
