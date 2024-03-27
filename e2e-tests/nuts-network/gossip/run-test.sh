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

echo "------------------------------------"
echo "Creating root"
echo "------------------------------------"

curl -s -X POST http://localhost:18081/internal/vdr/v1/did >/dev/null

sleep 2

# create 20 new DID documents on each node
echo "------------------------------------"
echo "Creating transactions"
echo "------------------------------------"

for _ in {1..20}
do
   curl -s -X POST http://localhost:18081/internal/vdr/v1/did >/dev/null
   curl -s -X POST http://localhost:28081/internal/vdr/v1/did >/dev/null
   curl -s -X POST http://localhost:38081/internal/vdr/v1/did >/dev/null
   curl -s -X POST http://localhost:48081/internal/vdr/v1/did >/dev/null
done

echo "------------------------------------"
echo "Performing assertions..."
echo "------------------------------------"

waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 81 10
waitForTXCount "NodeD" "http://localhost:48081/status/diagnostics" 81 10

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
