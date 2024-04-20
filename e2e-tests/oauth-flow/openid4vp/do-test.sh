#!/usr/bin/env bash
source ../../util.sh

echo "------------------------------------"
echo "Running test ${1}"
echo "------------------------------------"

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d --remove-orphans
docker compose up --wait nodeA nodeB nodeA-backend nodeB-backend

echo "------------------------------------"
echo "Registering DIDs..."
echo "------------------------------------"
source "${1}.sh"

# Issue NutsOrganizationCredential for Vendor B
REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${PARTY_B_DID}\", \"credentialSubject\": {\"id\":\"${PARTY_B_DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"withStatusList2021Revocation\": false}"
RESPONSE=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential to node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $RESPONSE | curl -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/holder/${PARTY_B_DID}/vc -H "Content-Type:application/json")
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
REQUEST="{\"verifier\":\"${PARTY_A_DID}\",\"scope\":\"test\", \"preauthorized_user\":{\"id\":\"1\", \"name\": \"John Doe\", \"role\": \"Janitor\"}, \"redirect_uri\":\"http://callback\"}"
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v2/${PARTY_B_DID}/request-user-access-token -H "Content-Type:application/json")
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
RESPONSE=$(curl --cookie-jar ./node-B/cookies.txt -D ./node-B/headers.txt $LOCATION -k)
if grep -q 'Location' ./node-B/headers.txt; then
  LOCATION=$(grep 'Location' ./node-B/headers.txt | sed -E 's/Location: (.*)/\1/' | tr -d '\r')
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
RESPONSE=$(curl -D ./node-B/headers.txt $LOCATION -k)
if grep -q 'Location' ./node-B/headers.txt; then
  LOCATION=$(grep 'Location' ./node-B/headers.txt | sed -E 's/Location: (.*)/\1/' | tr -d '\r')
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
RESPONSE=$(curl  --cookie ./node-B/cookies.txt -D ./node-B/headers.txt $LOCATION -k)
if grep -q 'Location' ./node-B/headers.txt; then
  LOCATION=$(grep 'Location' ./node-B/headers.txt | sed -E 's/Location: (.*)/\1/' | tr -d '\r')
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
RESPONSE=$(curl -D ./node-B/headers.txt $LOCATION -k)
if grep -q 'Location' ./node-B/headers.txt; then
  echo $LOCATION
else
  echo $RESPONSE
  echo "FAILED: Could not get token from node-B" 1>&2
  exitWithDockerLogs 1
fi

echo "--------------------------------------"
echo "Use flow token to get access token ..."
echo "--------------------------------------"

RESPONSE=$(curl http://localhost:28081/internal/auth/v2/accesstoken/$SESSION -k)
if echo $RESPONSE | grep -q "access_token"; then
  echo $RESPONSE | sed -E 's/.*"access_token":"([^"]*).*/\1/' > ./node-B/accesstoken.txt
  echo "access token stored in ./node-B/accesstoken.txt"
else
  echo "FAILED: Could not get access token from node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi


echo "------------------------------------"
echo "Retrieving data..."
echo "------------------------------------"
RESPONSE=$(docker compose exec nodeB-backend curl http://resource:80/resource -H "Authorization: bearer $(cat ./node-B/accesstoken.txt)")
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
rm ./node-B/*.txt
