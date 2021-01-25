.PHONY: test run-generators update-docs

run-generators: gen-readme gen-mocks gen-api

gen-readme:
	./generate_readme.sh

gen-mocks:
	mockgen -destination=crypto/mock.go -package=crypto -source=crypto/interface.go -self_package github.com/nuts-foundation/nuts-node/crypto
	mockgen -destination=vdr/types/mock.go -package=types -source=vdr/types/interface.go -self_package github.com/nuts-foundation/nuts-node/vdr/types --imports did=github.com/nuts-foundation/go-did

gen-api:
	oapi-codegen -generate types,server,client -package v1 docs/_static/crypto/v1.yaml > crypto/api/v1/generated.go
	oapi-codegen -generate types,server,client,skip-prune -package v1 -exclude-schemas DIDDocument,DIDDocumentMetadata,Service,VerificationMethod docs/_static/vdr/v1.yaml > vdr/api/v1/generated.go

gen-docs:
	go run ./docs

test:
	go test ./...

update-docs: gen-docs gen-readme
