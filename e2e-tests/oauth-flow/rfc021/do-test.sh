#!/usr/bin/env bash
source ../../util.sh
echo "===================================="
echo "Running test on database: ${1}"
echo "===================================="
source "${1}.sh"

# Build a docker compose command with the shared services and DB service-specific compose file
db_dc="docker compose -f docker-compose.yml -f ${1}.yml"

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
$db_dc down
$db_dc rm -f -v

echo "------------------------------------"
echo "Creating databases..."
echo "------------------------------------"
$db_dc up --wait db
createDB "${db_dc}"

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
$db_dc up -d
$db_dc up --wait nodeA nodeA-backend nodeB nodeB-backend

echo "------------------------------------"
echo "Registering vendors..."
echo "------------------------------------"
# Register Vendor A
VENDOR_A_DIDDOC=$($db_dc exec nodeA-backend nuts vdr create-did --v2)
VENDOR_A_DID=$(echo $VENDOR_A_DIDDOC | jq -r .id)
echo Vendor A DID: $VENDOR_A_DID

# Register Vendor B
VENDOR_B_DIDDOC=$($db_dc exec nodeB-backend nuts vdr create-did --v2)
VENDOR_B_DID=$(echo $VENDOR_B_DIDDOC | jq -r .id)
echo Vendor B DID: $VENDOR_B_DID

# Issue NutsOrganizationCredential for Vendor B
REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${VENDOR_B_DID}\", \"credentialSubject\": {\"id\":\"${VENDOR_B_DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"withStatusList2021Revocation\": false}"
RESPONSE=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential to node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $RESPONSE | curl -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/holder/${VENDOR_B_DID}/vc -H "Content-Type:application/json")
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
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v2/$VENDOR_B_DID/request-service-access-token -H "Content-Type: application/json" -v)
if echo $RESPONSE | grep -q "access_token"; then
  echo $RESPONSE | sed -E 's/.*"access_token":"([^"]*).*/\1/' > ./node-B/accesstoken.txt
  echo "access token stored in ./node-B/accesstoken.txt"
else
  echo "FAILED: Could not get access token from node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

ACCESS_TOKEN=$(cat ./node-B/accesstoken.txt)

echo "------------------------------------"
echo "Create DPoP header..."
echo "------------------------------------"
REQUEST="{\"method\":\"GET\",\"url\":\"https://nodeA:443/resource\", \"token\":\"$ACCESS_TOKEN\"}"
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v2/$VENDOR_B_DID/dpop -H "Content-Type: application/json" -v)
if echo $RESPONSE | grep -q "dpop"; then
  echo $RESPONSE | sed -E 's/.*"dpop":"([^"]*).*/\1/' > ./node-B/dpop.txt
  echo "dpop token stored in ./node-B/dpop.txt"
else
  echo "FAILED: Could not get dpop token from node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

DPOP=$(cat ./node-B/dpop.txt)

echo "------------------------------------"
echo "Retrieving data..."
echo "------------------------------------"
RESPONSE=$($db_dc exec nodeB curl --http1.1 --insecure --cert /etc/nginx/ssl/server.pem --key /etc/nginx/ssl/key.pem https://nodeA:443/resource -H "Authorization: DPoP $ACCESS_TOKEN" -H "DPoP: $DPOP" -v)
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
$db_dc stop
rm node-*/*.txt