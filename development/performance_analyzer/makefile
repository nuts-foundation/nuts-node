.PHONY: build

build:
	docker build --tag nutsfoundation/nuts-node:dev .

build-master:
	docker build --tag nutsfoundation/nuts-node:master ../../

build-local: build-master build
