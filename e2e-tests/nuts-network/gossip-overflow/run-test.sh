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

# Wait for Nuts Network nodes to build connections
sleep 1

# create 200 new DID documents on each node
echo "------------------------------------"
echo "Creating transactions"
echo "------------------------------------"

for _ in {1..200}
do
   curl -s -X POST http://localhost:11323/internal/vdr/v1/did >/dev/null
done

echo "------------------------------------"
echo "Performing assertions..."
echo "------------------------------------"

waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 200 20

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
