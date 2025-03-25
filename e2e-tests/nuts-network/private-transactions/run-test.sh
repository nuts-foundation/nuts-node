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
echo "Create DB..."
echo "------------------------------------"
docker compose up --wait db
docker compose exec db psql -U postgres -c "CREATE DATABASE node_a"
docker compose exec db psql -U postgres -c "CREATE DATABASE node_b"

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
export NODE_A_DID=$(setupNode "http://localhost:18081" "nodeA:5555" "http://nodeA:8080")
printf "NodeDID for node-a: %s\n" "$NODE_A_DID"
# Wait for node B to receive the TXs created by node A, indicating the connection is working
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 3 10
export NODE_B_DID=$(setupNode "http://localhost:28081" "nodeB:5555" "http://nodeB:8080")
printf "NodeDID for node-b: %s\n" "$NODE_B_DID"
# Wait for node A to receive all TXs created by node B
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 6 10

# Issue NutsOrganizationCredential for Vendor B
REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${NODE_B_DID}\", \"credentialSubject\": {\"id\":\"${NODE_B_DID}\", \"organization\":{\"name\":\"Caresoft B\", \"city\":\"Caretown\"}},\"visibility\": \"public\"}"
RESPONSE=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential to node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
# Issue NutsOrganizationCredential for Vendor A
REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${NODE_A_DID}\", \"credentialSubject\": {\"id\":\"${NODE_A_DID}\", \"organization\":{\"name\":\"Caresoft A\", \"city\":\"Caretown\"}},\"visibility\": \"public\"}"
RESPONSE=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:18081/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential to node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 8 10
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 8 10

# Vendor A must trust 'NutsOrganizationCredential's from Vendor B
docker compose exec nodeA nuts vcr trust "NutsOrganizationCredential" "${NODE_B_DID}"
# Vendor B must trust its own 'NutsOrganizationCredential's since it's self-issued
docker compose exec nodeB nuts vcr trust "NutsOrganizationCredential" "${NODE_A_DID}"

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
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 10 10
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 10 10

if [ $(searchAuthCredentials "http://localhost:18081" | jq ".verifiableCredentials[].verifiableCredential.id" | wc -l) -ne "2" ]; then
  echo "failed to find NutsAuthorizationCredentials on Node-A"
  exitWithDockerLogs 1
fi

if [ $(searchAuthCredentials "http://localhost:28081" | jq ".verifiableCredentials[].verifiableCredential.id" | wc -l) -ne "2" ]; then
  echo "failed to find NutsAuthorizationCredentials on Node-B"
  exitWithDockerLogs 1
fi


echo "------------------------------------"
echo "Sign contract..."
echo "------------------------------------"

# draw up a contract
REQUEST="{\"type\": \"PractitionerLogin\",\"language\": \"EN\",\"version\": \"v3\",\"legalEntity\": \"${NODE_B_DID}\"}"
RESPONSE=$(echo $REQUEST | curl -X PUT --data-binary @- http://localhost:28081/internal/auth/v1/contract/drawup -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "PractitionerLogin"; then
  echo $RESPONSE | sed -E 's/.*"message":"([^"]*).*/\1/' > ./node-B/data/contract.txt
  echo "Contract stored in ./node-B/data/contract.txt"
else
  echo "FAILED: Could not get contract drawn up at node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# sign the contract with dummy means
sed "s/BASE64_CONTRACT/$(cat ./node-B/data/contract.txt)/" ./node-B/createsigningsessionrequesttemplate.json > ./node-B/data/createsigningsessionrequest.json
RESPONSE=$(curl -X POST -s --data-binary "@./node-B/data/createsigningsessionrequest.json" http://localhost:28081/internal/auth/v1/signature/session -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "sessionPtr"; then
  SESSION=$(echo $RESPONSE | sed -E 's/.*"sessionID":"([^"]*).*/\1/')
  echo $SESSION
else
  echo "FAILED: Could not get contract signed at node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# poll once for status created
RESPONSE=$(curl "http://localhost:28081/internal/auth/v1/signature/session/$SESSION")
if echo $RESPONSE | grep -q "created"; then
  echo $RESPONSE
else
  echo "FAILED: Could not get session status from node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# poll twice for status success
RESPONSE=$(curl "http://localhost:28081/internal/auth/v1/signature/session/$SESSION")
if echo $RESPONSE | grep -q "in-progress"; then
  echo $RESPONSE
else
  echo "FAILED: Could not get session status from node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# poll three times for status completed
RESPONSE=$(curl "http://localhost:28081/internal/auth/v1/signature/session/$SESSION")
if echo $RESPONSE | grep -q "completed"; then
  echo $RESPONSE | sed -E 's/.*"verifiablePresentation":(.*\]}).*/\1/' > ./node-B/data/vp.txt
  echo "VP stored in ./node-B/data/vp.txt"
else
  echo "FAILED: Could not get session status from node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Add more credentials..."
echo "------------------------------------"
# Create JWT bearer token
VP=$(cat ./node-B/data/vp.txt)
VC1=$(searchAuthCredentials "http://localhost:28081" | jq ".verifiableCredentials[0].verifiableCredential")
VC2=$(searchAuthCredentials "http://localhost:28081" | jq ".verifiableCredentials[1].verifiableCredential")

#
#for i in {1..10000}; do
#  vcNodeA=$(createAuthCredential "http://localhost:18081" "$NODE_A_DID" "$NODE_B_DID")
#  vcNodeB=$(createAuthCredential "http://localhost:28081" "$NODE_B_DID" "$NODE_A_DID")
#  echo $i
#done

waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 10 60
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 10 60

echo "------------------------------------"
echo "Perform OAuth 2.0 flow..."
echo "------------------------------------"

REQUESTA="{\"credentials\": [${VC1}],\"authorizer\":\"${NODE_A_DID}\",\"requester\":\"${NODE_B_DID}\",\"identity\":${VP},\"service\":\"test\"}"
REQUESTB="{\"credentials\": [${VC2}],\"authorizer\":\"${NODE_A_DID}\",\"requester\":\"${NODE_B_DID}\",\"identity\":${VP},\"service\":\"test\"}"
for i in {1..40}; do
  for i in {1..100}; do
    echo $REQUESTA | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v1/request-access-token -H "Content-Type:application/json" > /dev/null &
    echo $REQUESTB | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v1/request-access-token -H "Content-Type:application/json" > /dev/null &
  done
 sleep 1
done

RESPONSE=$(echo $REQUESTA | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v1/request-access-token -H "Content-Type:application/json" -v)
RESPONSE=$(echo $REQUESTB | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v1/request-access-token -H "Content-Type:application/json" -v)


#if echo $RESPONSE | grep -q "access_token"; then
#  echo $RESPONSE | sed -E 's/.*"access_token":"([^"]*).*/\1/' > ./node-B/data/accesstoken.txt
#  echo "access token stored in ./node-B/data/accesstoken.txt"
#else
#  echo "FAILED: Could not get JWT access token from node-A" 1>&2
#  echo $RESPONSE
#  exitWithDockerLogs 1
#fi

#
#echo "------------------------------------"
#echo "Revoking NutsAuthorizationCredential..."
#echo "------------------------------------"
#revokeCredential "http://localhost:18081" "${vcNodeA}"
#revokeCredential "http://localhost:28081" "${vcNodeB}"
#
## Wait for transactions to sync
#waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 12 10
#waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 12 10
#
#if [ $(searchAuthCredentials "http://localhost:18081" | jq ".verifiableCredentials[].verifiableCredential.id" | wc -l) -ne "0" ]; then
#  echo "NutsAuthorizationCredentials should have been revoked so they can't be resolved on Node-A"
#  exitWithDockerLogs 1
#fi
#
#if [ $(searchAuthCredentials "http://localhost:28081" | jq ".verifiableCredentials[].verifiableCredential.id" | wc -l) -ne "0" ]; then
#  echo "NutsAuthorizationCredentials should have been revoked so they can't be resolved on Node-B"
#  exitWithDockerLogs 1
#fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
#docker compose stop
#exitWithDockerLogs 0