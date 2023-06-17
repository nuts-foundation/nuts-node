#!/usr/bin/env bash

set -e

source ../../util.sh

function findNodeDID() {
  egrep -o 'nodedid:.*' $1 | awk '{print $2}'
}

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
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d

waitForDCService nodeA
waitForDCService nodeB

# Wait for Nuts Network nodes to build connections
sleep 5

echo "------------------------------------"
echo "Asserting..."
echo "------------------------------------"

didNodeA=$(findNodeDID "node-A/nuts.yaml")
printf "NodeDID for node A: %s\n" "$didNodeA"

didNodeB=$(findNodeDID "node-B/nuts.yaml")
printf "NodeDID for node B: %s\n" "$didNodeB"

vcNodeA=$(createAuthCredential "http://localhost:11323" "$didNodeA" "$didNodeB")
printf "VC issued by node A: %s\n" "$vcNodeA"
vcNodeB=$(createAuthCredential "http://localhost:21323" "$didNodeB" "$didNodeA")
printf "VC issued by node B: %s\n" "$vcNodeB"

# Wait for transactions to sync
sleep 10

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
sleep 5

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

# cleanup: remove nodeDID from configs
removeNodeDID ./node-A/nuts.yaml
removeNodeDID ./node-B/nuts.yaml
