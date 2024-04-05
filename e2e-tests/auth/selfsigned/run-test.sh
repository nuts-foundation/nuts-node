#!/usr/bin/env bash
source ../../util.sh

set -e # make script fail if any of the tests returns a non-zero exit code

# Shut down existing containers
docker compose stop

# Start new stack
docker compose up --wait


go test -v --tags=e2e_tests .

docker compose stop