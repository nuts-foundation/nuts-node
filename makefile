test:
	go test ./...

update-docs:
	go run ./docs
	./generate_readme.sh
