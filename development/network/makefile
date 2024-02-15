.PHONY: build run

build-and-runs: build run

build:
	docker build ../../ --tag nutsfoundation/nuts-node:latest

run:
	docker compose up

generate:
	./generate.sh
