#!/usr/bin/env bash

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose stop
docker compose rm -f -v

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d
docker compose up --wait nodeA nodeB

echo "------------------------------------"
echo "Creating root"
echo "------------------------------------"
curl -s -X POST http://localhost:11323/internal/vdr/v1/did >/dev/null
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 1 10
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 1 10

# create 20 new DID documents on each node
echo "------------------------------------"
echo "Creating transactions"
echo "------------------------------------"
for _ in {1..20}
do
   curl -s -X POST http://localhost:11323/internal/vdr/v1/did >/dev/null
   curl -s -X POST http://localhost:21323/internal/vdr/v1/did >/dev/null
done

echo "----------------------------------------"
echo "Performing assertions before restart..."
echo "----------------------------------------"
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 41 10
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 41 10

echo "------------------------------------"
echo "Restarting Docker containers..."
echo "------------------------------------"
docker compose stop
docker compose up -d
docker compose up --wait nodeA nodeB

echo "----------------------------------------"
echo "Performing assertions after restart..."
echo "----------------------------------------"
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 41 10
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 41 10

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
