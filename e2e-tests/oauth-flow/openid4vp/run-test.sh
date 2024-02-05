#!/usr/bin/env bash
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
docker compose up -d --remove-orphans
docker compose up --wait nodeA nodeB

echo "------------------------------------"
echo "Registering vendors..."
echo "------------------------------------"

# Register Party A
PARTY_A_DIDDOC=$(docker compose exec nodeA nuts vdr create-did --v2)
PARTY_A_DID=$(echo $PARTY_A_DIDDOC | jq -r .id)
echo Vendor A DID: $PARTY_A_DID

# Register Vendor B
PARTY_B_DIDDOC=$(docker compose exec nodeB nuts vdr create-did --v2)
PARTY_B_DID=$(echo $PARTY_B_DIDDOC | jq -r .id)
echo Vendor B DID: $PARTY_B_DID

# Issue NutsOrganizationCredential for Vendor B
REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${PARTY_B_DID}\", \"credentialSubject\": {\"id\":\"${PARTY_B_DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"publishToNetwork\": false}"
RESPONSE=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:21323/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential to node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $RESPONSE | curl -X POST --data-binary @- http://localhost:21323/internal/vcr/v2/holder/${PARTY_B_DID}/vc -H "Content-Type:application/json")
if echo $RESPONSE == ""; then
  echo "VC stored in wallet"
else
  echo "FAILED: Could not load NutsOrganizationCredential in node-B wallet" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Request access token call"
echo "---------------------------------------"
# Request access token
REQUEST="{\"verifier\":\"${PARTY_A_DID}\",\"scope\":\"test\", \"user_id\":\"1\", \"redirect_uri\":\"http://callback\"}"
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:21323/internal/auth/v2/${PARTY_B_DID}/request-user-access-token -H "Content-Type:application/json" -v)
if echo $RESPONSE | grep -q "redirect_uri"; then
  LOCATION=$(echo $RESPONSE | sed -E 's/.*"redirect_uri":"([^"]*).*/\1/')
  SESSION=$(echo $RESPONSE | sed -E 's/.*"session_id":"([^"]*).*/\1/')
  echo "REDIRECTURL: $LOCATION"
  echo "SESSION: $SESSION"
else
  echo $RESPONSE
  echo "FAILED: Could not get redirect_uri from node-B" 1>&2
  exitWithDockerLogs 1
fi

echo "--------------------------------------"
echo "Redirect user to local OAuth server..."
echo "--------------------------------------"

LOCATION=$(echo $LOCATION | sed -E 's/nodeB/localhost:20443/')
RESPONSE=$(curl -D ./node-B/data/headers.txt $LOCATION -v -k)
if grep -q 'Location' ./node-B/data/headers.txt; then
  LOCATION=$(grep 'Location' ./node-B/data/headers.txt | sed -E 's/Location: (.*)/\1/' | tr -d '\r')
  echo "REDIRECTURL: $LOCATION"
else
  echo $RESPONSE
  echo "FAILED: Could not get redirectURL from node-B" 1>&2
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Redirect user to remote OAuth server..."
echo "---------------------------------------"

LOCATION=$(echo $LOCATION | sed -E 's/nodeA/localhost:10443/')
RESPONSE=$(curl -D ./node-B/data/headers.txt $LOCATION -v -k)
if grep -q 'Location' ./node-B/data/headers.txt; then
  LOCATION=$(grep 'Location' ./node-B/data/headers.txt | sed -E 's/Location: (.*)/\1/' | tr -d '\r')
  echo "REDIRECTURL: $LOCATION"
else
  echo $RESPONSE
  echo "FAILED: Could not get redirectURL from node-A" 1>&2
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Build VP..."
echo "---------------------------------------"

LOCATION=$(echo $LOCATION | sed -E 's/nodeB/localhost:20443/')
RESPONSE=$(curl -D ./node-B/data/headers.txt $LOCATION -v -k)
if grep -q 'Location' ./node-B/data/headers.txt; then
  LOCATION=$(grep 'Location' ./node-B/data/headers.txt | sed -E 's/Location: (.*)/\1/' | tr -d '\r')
  echo "REDIRECTURL: $LOCATION"
else
  echo $RESPONSE
  echo "FAILED: Could not get redirectURL from node-B" 1>&2
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Redirect user to local OAuth server ..."
echo "---------------------------------------"

LOCATION=$(echo $LOCATION | sed -E 's/nodeB/localhost:20443/')
RESPONSE=$(curl -D ./node-B/data/headers.txt $LOCATION -v -k)
if grep -q 'Location' ./node-B/data/headers.txt; then
  echo $LOCATION
else
  echo $RESPONSE
  echo "FAILED: Could not get token from node-B" 1>&2
  exitWithDockerLogs 1
fi

echo "--------------------------------------"
echo "Use flow token to get access token ..."
echo "--------------------------------------"

RESPONSE=$(curl http://localhost:21323/internal/auth/v2/accesstoken/$SESSION -v -k)
if echo $RESPONSE | grep -q "access_token"; then
  echo $RESPONSE | sed -E 's/.*"access_token":"([^"]*).*/\1/' > ./node-B/data/accesstoken.txt
  echo "access token stored in ./node-B/data/accesstoken.txt"
else
  echo "FAILED: Could not get access token from node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi


echo "------------------------------------"
echo "Retrieving data..."
echo "------------------------------------"
RESPONSE=$(docker compose exec nodeB curl http://resource:80/resource -H "Authorization: bearer $(cat ./node-B/data/accesstoken.txt)" -v)
if echo $RESPONSE | grep -q "OK"; then
  echo "success!"
else
  echo "FAILED: Could not get resource from resource" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
