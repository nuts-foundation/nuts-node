#!/usr/bin/env bash

set -e

source ../../util.sh

function searchAuthCredentials() {
  printf '{
    "query": {
      "@context": ["https://www.w3.org/2018/credentials/v1", "https://nuts.nl/credentials/v1"],
      "type": ["VerifiableCredential" ,"NutsAuthorizationCredential"],
      "credentialSubject": {
        "subject": "urn:oid:2.16.840.1.113883.2.4.6.3:123456780"
      }
    },
    "searchOptions": {
       "allowUntrustedIssuer": true
    }
  }' | curl -s -X POST "$1/internal/vcr/v2/search" -H "Content-Type: application/json" --data-binary @-
}

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v
rm -rf ./node-*/data

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
# 'data' dirs will be created with root owner by docker if they do not exit.
# This creates permission issues on CI, since we manually delete the network/connections.db file.
mkdir -p ./node-A/data/network ./node-B/data/network
# Empty node DIDs to avoid warning in Docker logs
export NODE_A_DID=
export NODE_B_DID=
export BOOTSTRAP_NODES=nodeA:5555
docker compose up --wait

echo "------------------------------------"
echo "Creating NodeDIDs..."
echo "------------------------------------"
export NODE_A_DID=$(setupNode "http://localhost:11323" "nodeA:5555")
printf "NodeDID for node-a: %s\n" "$NODE_A_DID"
# Wait for node B to receive the TXs created by node A, indicating the connection is working
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 2 10
export NODE_B_DID=$(setupNode "http://localhost:21323" "nodeB:5555")
printf "NodeDID for node-b: %s\n" "$NODE_B_DID"
# Wait for node A to receive all TXs created by node B
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 4 10

echo "------------------------------------"
echo "Restarting with NodeDID set..."
echo "------------------------------------"
# Start without bootstrap node, to enforce authenticated, discovered connections (required for private transactions)
export BOOTSTRAP_NODES=
docker compose stop
# Delete nodes' address books to avoid persisting initial "new node" delay, allowing to connect to each other immediately
rm -rf ./node-*/data/network/connections.db
docker compose up --wait

echo "------------------------------------"
echo "Issuing private credentials..."
echo "------------------------------------"
vcNodeA=$(createAuthCredential "http://localhost:11323" "$NODE_A_DID" "$NODE_B_DID")
printf "VC issued by node A: %s\n" "$vcNodeA"
vcNodeB=$(createAuthCredential "http://localhost:21323" "$NODE_B_DID" "$NODE_A_DID")
printf "VC issued by node B: %s\n" "$vcNodeB"

# Wait for transactions to sync
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 6 10
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 6 10

if [ $(searchAuthCredentials "http://localhost:11323" | jq ".verifiableCredentials[].verifiableCredential.id" | wc -l) -ne "2" ]; then
  echo "failed to find NutsAuthorizationCredentials on Node-A"
  exitWithDockerLogs 1
fi

if [ $(searchAuthCredentials "http://localhost:21323" | jq ".verifiableCredentials[].verifiableCredential.id" | wc -l) -ne "2" ]; then
  echo "failed to find NutsAuthorizationCredentials on Node-B"
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Revoking NutsAuthorizationCredential..."
echo "------------------------------------"
revokeCredential "http://localhost:11323" "${vcNodeA}"
revokeCredential "http://localhost:21323" "${vcNodeB}"

# Wait for transactions to sync
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 8 10
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 8 10

if [ $(searchAuthCredentials "http://localhost:11323" | jq ".verifiableCredentials[].verifiableCredential.id" | wc -l) -ne "0" ]; then
  echo "NutsAuthorizationCredentials should have been revoked so they can't be resolved on Node-A"
  exitWithDockerLogs 1
fi

if [ $(searchAuthCredentials "http://localhost:21323" | jq ".verifiableCredentials[].verifiableCredential.id" | wc -l) -ne "0" ]; then
  echo "NutsAuthorizationCredentials should have been revoked so they can't be resolved on Node-B"
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop