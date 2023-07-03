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
docker compose up --wait

echo "------------------------------------"
echo "Performing assertions..."
echo "------------------------------------"
# Wait for Nuts Network nodes to build connections
waitForDiagnostic "nodeA" connected_peers_count 1
waitForDiagnostic "nodeB" connected_peers_count 1

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
