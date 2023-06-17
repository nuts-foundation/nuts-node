#!/usr/bin/env bash

set -e

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"

docker compose down
docker compose rm -f -v
rm -rf ./node-*/data
removeNodeDID ./node-A/nuts.yaml
removeNodeDID ./node-B/nuts.yaml

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"

docker compose up -d

waitForDCService nodeA
waitForDCService nodeB

# Wait for Nuts Network nodes to build connections
sleep 5

echo "------------------------------------"
echo "Creating NodeDIDs..."
echo "------------------------------------"

didNodeA=$(setupNode "http://localhost:11323" "nodeA:5555")
printf "NodeDID for node-a: %s\n" "$didNodeA"

# Restart nodeA now that it has >0 did documents with a NutsComm endpoint.
# This tricks the node into thinking it is not 'new' so it can bypass the service discovery delay for new nodes and immediately setup an authenticated connection.
# (nodeB will store this delay as a backoff for nodeA, so nodeA needs to discover and connect to nodeB after the restart)
docker compose restart nodeA
waitForDCService nodeA

# Wait for the transactions to be processed (will be the root transaction for both nodes)
sleep 5

didNodeB=$(setupNode "http://localhost:21323" "nodeB:5555")
printf "NodeDID for node-b: %s\n" "$didNodeB"

# Wait for the transactions to be processed
sleep 5

echo "  nodedid: $didNodeA" >> node-A/nuts.yaml
echo "  nodedid: $didNodeB" >> node-B/nuts.yaml

docker compose stop
