#!/usr/bin/env bash

set -e

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v
rm -rf ./node-*/data
mkdir ./node-A/data ./node-B/data  # 'data' dirs will be created with root owner by docker if they do not exit. This creates permission issues on CI.

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d

waitForDCService nodeA
waitForDCService nodeB

echo "------------------------------------"
echo "Creating NodeDIDs..."
echo "------------------------------------"

didNodeA=$(setupNode "http://localhost:11323" "nodeA:5555")
printf "NodeDID for node-a: %s\n" "$didNodeA"
# Register service required for OpenID4VCI discovery
registerStringService "http://localhost:11323" "$didNodeA" "node-http-services-baseurl" "https://nodeA"

# Wait for node B to receive the TXs created by node A, indicating the connection is working
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 3 10

didNodeB=$(setupNode "http://localhost:21323" "nodeB:5555")
printf "NodeDID for node-b: %s\n" "$didNodeB"
# Register service required for OpenID4VCI discovery
registerStringService "http://localhost:21323" "$didNodeB" "node-http-services-baseurl" "https://nodeB"

# Wait for node A to receive all TXs created by node B
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 6 10

echo "------------------------------------"
echo "Issuing credential..."
echo "------------------------------------"
vcNodeA=$(createAuthCredential "http://localhost:11323" "$didNodeA" "$didNodeB")
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
