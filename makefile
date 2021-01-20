.PHONY: test run-generators update-docs

run-generators:
	mockgen -destination=crypto/mock/mock.go -package=mock -source=crypto/interface.go
	oapi-codegen -generate types,server,client -package v1 docs/_static/crypto/v1.yaml > crypto/api/v1/generated.go
	oapi-codegen -generate types,server,client -package v1 docs/_static/did/v1.yaml > vdr/api/v1/generated.go

test:
	go test ./...

update-docs:
	go run ./docs
	./generate_readme.sh
