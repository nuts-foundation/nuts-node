#!/usr/bin/env bash

set -e

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v
rm -rf ./node-data/*
rm -rf ./node-backup/*
removeNodeDID ./node-A/nuts.yaml
mkdir -p ./node-data ./node-backup ./node-backup/vcr/ # 'data' dirs will be created with root owner by docker if they do not exit. This creates permission issues on CI.

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d
waitForDCService nodeA

echo "------------------------------------"
echo "Creating NodeDID..."
echo "------------------------------------"
nodeDID=$(setupNode "http://localhost:11323" nodeA:5555)


echo "  nodedid: $nodeDID" >> node-A/nuts.yaml

docker compose stop
