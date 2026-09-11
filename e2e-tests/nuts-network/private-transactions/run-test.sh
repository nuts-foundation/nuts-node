#!/usr/bin/env bash

set -e

USER=$UID

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

# waitForAuthCredentialCount polls the credential search on a node until it returns the expected number of
# NutsAuthorizationCredentials. The transaction count reaching its expected value only means the transaction is
# stored: the VCR applies the credential or revocation afterwards through an asynchronous subscriber.
# Args: service name, node URL, expected number of credentials, timeout in seconds
function waitForAuthCredentialCount() {
  local service_name=$1
  local url=$2
  local expected=$3
  local timeout=$4
  local count=""
  printf "Waiting for service '%s' to return %s NutsAuthorizationCredentials" "$service_name" "$expected"
  local retry=0
  while [ $retry -lt $timeout ]; do
    count=$(searchAuthCredentials "$url" | jq ".verifiableCredentials | length")
    if [ "$count" == "$expected" ]; then
      echo ""
      return 0
    fi
    printf "."
    sleep 1
    retry=$((retry+1))
  done
  echo ""
  echo "FAILED: Service '$service_name' returned ${count:-no} NutsAuthorizationCredentials after ${timeout} seconds, expected $expected"
  exitWithDockerLogs 1
}

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
# Empty node DIDs to avoid warning in Docker logs
export NODE_A_DID=
export NODE_B_DID=
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
echo "Creating NodeDIDs..."
echo "------------------------------------"
export NODE_A_DID=$(setupNode "http://localhost:18081" "nodeA:5555")
printf "NodeDID for node-a: %s\n" "$NODE_A_DID"
# Wait for node B to receive the TXs created by node A, indicating the connection is working
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 2 10
export NODE_B_DID=$(setupNode "http://localhost:28081" "nodeB:5555")
printf "NodeDID for node-b: %s\n" "$NODE_B_DID"
# Wait for node A to receive all TXs created by node B
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 4 10

echo "------------------------------------"
echo "Restarting with NodeDID set..."
echo "------------------------------------"
# Start without bootstrap node, to enforce authenticated, discovered connections (required for private transactions)
export BOOTSTRAP_NODES=
# Delete nodes' address books to avoid persisting initial "new node" delay, allowing to connect to each other immediately
docker compose exec nodeA rm -f /opt/nuts/data/network/connections.db
docker compose exec nodeB rm -f /opt/nuts/data/network/connections.db
docker compose stop
docker compose up --wait

echo "------------------------------------"
echo "Issuing private credentials..."
echo "------------------------------------"
vcNodeA=$(createAuthCredential "http://localhost:18081" "$NODE_A_DID" "$NODE_B_DID")
printf "VC issued by node A: %s\n" "$vcNodeA"
vcNodeB=$(createAuthCredential "http://localhost:28081" "$NODE_B_DID" "$NODE_A_DID")
printf "VC issued by node B: %s\n" "$vcNodeB"

# Wait for transactions to sync
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 6 10
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 6 10

waitForAuthCredentialCount "NodeA" "http://localhost:18081" 2 10
waitForAuthCredentialCount "NodeB" "http://localhost:28081" 2 10

echo "------------------------------------"
echo "Revoking NutsAuthorizationCredential..."
echo "------------------------------------"
revokeCredential "http://localhost:18081" "${vcNodeA}"
revokeCredential "http://localhost:28081" "${vcNodeB}"

# Wait for transactions to sync
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 8 10
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 8 10

# The revocations must no longer resolve once the VCR has processed them
waitForAuthCredentialCount "NodeA" "http://localhost:18081" 0 10
waitForAuthCredentialCount "NodeB" "http://localhost:28081" 0 10

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop