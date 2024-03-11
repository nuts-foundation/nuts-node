#!/usr/bin/env bash

set -e

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
# Empty node DIDs to avoid warning in Docker logs
export NODEA_DID=
export NODEB_DID=
export BOOTSTRAP_NODES=nodeA:5555
docker compose down
docker compose rm -f -v
rm -rf ./node-*/data

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
# 'data' dirs will be created with root owner by docker if they do not exit.
# This creates permission issues on CI, since we manually delete the network/connections.db file.
mkdir -p ./node-A/data/network ./node-B/data/network
docker compose up --wait

echo "------------------------------------"
echo "Creating NodeDIDs, waiting for Golden Hammer to register base URLs..."
echo "------------------------------------"
export NODEA_DID=$(setupNode "http://localhost:18081" "nodeA:5555")
printf "NodeDID for node A: %s\n" "$NODEA_DID"
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 2 10 # 2 for setupNode, 0 for GoldenHammer
export NODEB_DID=$(setupNode "http://localhost:28081" "nodeB:5555")
printf "NodeDID for node B: %s\n" "$NODEB_DID"
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 5 10 # 2 for setupNode, 1 for GoldenHammer

echo "------------------------------------"
echo "Restarting with NodeDID set..."
echo "------------------------------------"
# Start without bootstrap node, to enforce authenticated, discovered connections (required for private transactions)
export BOOTSTRAP_NODES=
# Delete nodes' address books to avoid persisting initial "new node" delay, allowing to connect to each other immediately
docker compose exec nodeA-backend rm -f /opt/nuts/data/network/connections.db
docker compose exec nodeB-backend rm -f /opt/nuts/data/network/connections.db
docker compose stop
docker compose up --wait

echo "------------------------------------"
echo "Issuing credential..."
echo "------------------------------------"
vcNodeA=$(createAuthCredential "http://localhost:18081" "$NODEA_DID" "$NODEB_DID")
printf "VC issued by node A: %s\n" "$vcNodeA"
vcNodeB=$(createAuthCredential "http://localhost:28081" "$NODEB_DID" "$NODEA_DID")
printf "VC issued by node B: %s\n" "$vcNodeB"

waitForDiagnostic "nodeA-backend" issued_credentials_count 1
waitForDiagnostic "nodeA-backend" credential_count 2
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 7 10 # 2 authz credentials
waitForDiagnostic "nodeB-backend" issued_credentials_count 1
waitForDiagnostic "nodeB-backend" credential_count 2
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 7 10 # 2 authz credentials

# Now the credential should be present on both nodeA and nodeB
echo $(readCredential "http://localhost:18081" $vcNodeA)
echo $(readCredential "http://localhost:28081" $vcNodeA)
echo $(readCredential "http://localhost:18081" $vcNodeB)
echo $(readCredential "http://localhost:28081" $vcNodeB)

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
