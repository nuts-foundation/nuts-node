.PHONY: test run-generators update-docs

run-generators: gen-readme gen-mocks gen-api

gen-readme:
	./generate_readme.sh

gen-mocks:
	mockgen -destination=crypto/mock/mock.go -package=mock -source=crypto/interface.go

gen-api:
	oapi-codegen -generate types,server,client -package v1 docs/_static/crypto/v1.yaml > crypto/api/v1/generated.go
	oapi-codegen -generate types,server,client -package v1 docs/_static/did/v1.yaml > vdr/api/v1/generated.go

gen-docs:
	go run ./docs

test:
	go test ./...

update-docs: gen-docs gen-readme
