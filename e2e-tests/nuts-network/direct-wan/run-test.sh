#!/usr/bin/env bash

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d
waitForDCService nodeA
waitForDCService nodeB

echo "------------------------------------"
echo "Performing assertions..."
echo "------------------------------------"
# Wait for Nuts Network nodes to build connections
sleep 5
# Assert that node A is connected to B and vice versa using diagnostics. It should look something like this:
assertDiagnostic "http://localhost:11323" "connected_peers_count: 1"
assertDiagnostic "http://localhost:21323" "connected_peers_count: 1"

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
