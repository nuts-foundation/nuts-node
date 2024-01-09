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
echo "Perform OAuth 2.0 rfc021 flow..."
echo "---------------------------------------"
# Request access token
REQUEST="{\"verifier\":\"${VENDOR_A_DID}\",\"scope\":\"test\"}"
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:21323/internal/auth/v2/$VENDOR_B_DID/request-access-token -H "Content-Type:application/json" -v)
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
RESPONSE=$(docker compose exec nodeB curl --http1.1 --insecure --cert /etc/nginx/ssl/server.pem --key /etc/nginx/ssl/key.pem https://nodeA:443/resource -H "Authorization: bearer $(cat ./node-B/data/accesstoken.txt)" -v)
if echo $RESPONSE | grep -q "OK"; then
  echo "success!"
else
  echo "FAILED: Could not get resource from node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
