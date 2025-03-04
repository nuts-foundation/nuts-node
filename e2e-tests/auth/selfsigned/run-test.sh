#!/usr/bin/env bash
source ../../util.sh

set -e # make script fail if any of the tests returns a non-zero exit code

# Shut down existing containers
docker compose stop
docker compose rm -f -v
rm -rf ./data
mkdir ./data

# Start new stack
docker compose up --wait


go test -v -count=1 --tags=e2e_tests .

docker compose stop