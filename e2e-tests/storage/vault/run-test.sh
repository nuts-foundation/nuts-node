#!/usr/bin/env bash

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v

echo "------------------------------------"
echo "Setting up Vault..."
echo "------------------------------------"
docker compose up --wait vault && sleep 2
docker compose exec -e VAULT_TOKEN=root vault vault secrets enable -version=1 -address=http://localhost:8200 kv

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up --wait

echo "------------------------------------"
echo "Create and update 2 DID documents..."
echo "------------------------------------"
DIDDOC_1=$(docker compose exec node nuts vdr create-did)
DID_1=$(echo $DIDDOC_1 | jq -r .id)
docker compose exec node nuts didman svc add "${DID_1}" testEndpoint "http://example.com"
DIDDOC_2=$(docker compose exec node nuts vdr create-did)
DID_2=$(echo $DIDDOC_2 | jq -r .id)
docker compose exec node nuts didman svc add "${DID_2}" testEndpoint "http://example.com"
waitForTXCount "Node" "http://localhost:18081/status/diagnostics" 4 10

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
