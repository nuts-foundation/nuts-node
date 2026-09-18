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
echo "Creating root"
echo "------------------------------------"

curl -s -X POST http://localhost:18081/internal/vdr/v1/did >/dev/null

# Every other node must have the root transaction before it creates transactions of its own,
# otherwise it creates a second root and the DAGs can never be merged.
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 1 10
waitForTXCount "NodeC" "http://localhost:38081/status/diagnostics" 1 10
waitForTXCount "NodeD" "http://localhost:48081/status/diagnostics" 1 10

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

waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 81 30
waitForTXCount "NodeD" "http://localhost:48081/status/diagnostics" 81 30

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
