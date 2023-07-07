#!/usr/bin/env bash

set -e

source ../../util.sh

echo "------------------------------------"
echo "Setting up fresh environment"
echo "------------------------------------"
docker compose down
docker compose rm -f -v
rm -rf ./node-*/data
mkdir ./node-A/data ./node-B/data  # 'data' dirs will be created with root owner by docker if they do not exit. This creates permission issues on CI.
docker compose up --wait

echo "------------------------------------"
echo "Creating NodeDIDs, waiting for Golden Hammer to register base URLs..."
echo "------------------------------------"
export NODEA_DID=$(setupNode "http://localhost:11323" "nodeA:5555")
printf "NodeDID for node A: %s\n" "$NODEA_DID"
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 3 10 # 2 for setupNode, 1 for GoldenHammer
export NODEB_DID=$(setupNode "http://localhost:21323" "nodeB:5555")
printf "NodeDID for node B: %s\n" "$NODEB_DID"
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 6 10 # 2 for setupNode, 1 for GoldenHammer

echo "------------------------------------"
echo "Issuing credential..."
echo "------------------------------------"
vcNodeA=$(createAuthCredential "http://localhost:11323" "$NODEA_DID" "$NODEB_DID")
printf "VC issued by node A: %s\n" "$vcNodeA"

waitForDiagnostic "nodeA" issued_credentials_count 1
waitForDiagnostic "nodeB" credential_count 1

# Now the credential should be present on both nodeA and nodeB
echo $(readCredential "http://localhost:11323" $vcNodeA)
echo $(readCredential "http://localhost:21323" $vcNodeA)

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
