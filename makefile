.PHONY: test run-generators update-docs

run-generators:
	mockgen -destination=crypto/mock/mock.go -package=mock -source=crypto/interface.go

test:
	go test ./...

update-docs:
	go run ./docs
	./generate_readme.sh
