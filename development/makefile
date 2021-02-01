.PHONY: build run

build-and-runs: build run

build:
	docker build ../ --tag nutsfoundation/nuts:latest

run:
	docker-compose up

generate:
	./generate.sh
