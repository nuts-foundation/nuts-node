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
docker compose up -d
docker compose up --wait nodeA nodeA-backend nodeB nodeB-backend

echo "------------------------------------"
echo "Registering vendors..."
echo "------------------------------------"
# Register Vendor A
VENDOR_A_DIDDOC=$(docker compose exec nodeA-backend nuts vdr create-did --v2)
VENDOR_A_DID=$(echo $VENDOR_A_DIDDOC | jq -r .id)
echo Vendor A DID: $VENDOR_A_DID

# Register Vendor B
VENDOR_B_DIDDOC=$(docker compose exec nodeB-backend nuts vdr create-did --v2)
VENDOR_B_DID=$(echo $VENDOR_B_DIDDOC | jq -r .id)
echo Vendor B DID: $VENDOR_B_DID

# Issue NutsOrganizationCredential for Vendor B
REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${VENDOR_B_DID}\", \"credentialSubject\": {\"id\":\"${VENDOR_B_DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"publishToNetwork\": false}"
RESPONSE=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:21323/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential to node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $RESPONSE | curl -X POST --data-binary @- http://localhost:21323/internal/vcr/v2/holder/${VENDOR_B_DID}/vc -H "Content-Type:application/json")
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
REQUEST="{\"verifier\":\"${VENDOR_A_DID}\",\"scope\":\"test\", \"userID\":\"1\", \"redirectURL\":\"http://callback\"}"
RESPONSE=$(echo $REQUEST | curl -D ./node-B/data/headers.txt -X POST -s --data-binary @- http://localhost:21323/internal/auth/v2/${VENDOR_B_DID}/request-access-token -H "Content-Type:application/json" -v)
if grep -q 'Location' ./node-B/data/headers.txt; then
  LOCATION=$(grep 'Location' ./node-B/data/headers.txt | sed -E 's/Location: (.*)/\1/' | tr -d '\r')
  echo "REDIRECTURL: $LOCATION"
else
  echo $RESPONSE
  echo "FAILED: Could not get redirectURL from node-B" 1>&2
  exitWithDockerLogs 1
fi

echo "--------------------------------------"
echo "Redirect user to local OAuth server..."
echo "--------------------------------------"

LOCATION=$(echo $LOCATION | sed -E 's/nodeB/localhost:20443/')
RESPONSE=$(curl -D ./node-B/data/headers.txt $LOCATION -v -k)
if grep -q 'location' ./node-B/data/headers.txt; then
  LOCATION=$(grep 'location' ./node-B/data/headers.txt | sed -E 's/location: (.*)/\1/' | tr -d '\r')
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
if grep -q 'location' ./node-B/data/headers.txt; then
  LOCATION=$(grep 'location' ./node-B/data/headers.txt | sed -E 's/location: (.*)/\1/' | tr -d '\r')
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
if grep -q 'location' ./node-B/data/headers.txt; then
  LOCATION=$(grep 'location' ./node-B/data/headers.txt | sed -E 's/location: (.*)/\1/' | tr -d '\r')
  echo "REDIRECTURL: $LOCATION"
else
  echo $RESPONSE
  echo "FAILED: Could not get redirectURL from node-B" 1>&2
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Redirect user to local OAuth server ..."
echo "---------------------------------------"

# todo, callback url is not registered yet

#LOCATION=$(echo $LOCATION | sed -E 's/nodeB/localhost:20443/')
#RESPONSE=$(curl -D ./node-B/data/headers.txt $LOCATION -v -k)
#echo $RESPONSE


echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
