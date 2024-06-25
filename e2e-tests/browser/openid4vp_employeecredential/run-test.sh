#!/usr/bin/env bash
source ../../util.sh

# Shut down existing containers
docker compose stop
docker compose rm -f -v

# Start new stack
docker compose up --wait

go test -v --tags=e2e_tests -count=1 .
if [ $? -ne 0 ]; then
	echo "ERROR: test failure"
	exitWithDockerLogs 1
fi

docker compose stop