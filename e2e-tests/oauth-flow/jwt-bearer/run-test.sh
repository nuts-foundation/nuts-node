#!/usr/bin/env bash
source ../../util.sh

dc="docker compose -f docker-compose.yml"

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
$dc down --remove-orphans
$dc rm -f -v

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
$dc up -d
$dc up --wait nodeA nodeA-backend nodeB nodeB-backend

echo "------------------------------------"
echo "Registering vendors..."
echo "------------------------------------"
# Register Vendor A
REQUEST="{\"subject\":\"vendorA\"}"
VENDOR_A_DIDDOC=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:18081/internal/vdr/v2/subject --header "Content-Type: application/json")
VENDOR_A_DID=$(echo $VENDOR_A_DIDDOC | jq -r .documents[0].id)
echo Vendor A DID: $VENDOR_A_DID

# Register Vendor B
REQUEST="{\"subject\":\"vendorB\"}"
VENDOR_B_DIDDOC=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:28081/internal/vdr/v2/subject --header "Content-Type: application/json")
VENDOR_B_DID=$(echo $VENDOR_B_DIDDOC | jq -r .documents[0].id)
echo Vendor B DID: $VENDOR_B_DID

# Issue NutsOrganizationCredential for Vendor B
REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${VENDOR_B_DID}\", \"credentialSubject\": {\"id\":\"${VENDOR_B_DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"withStatusList2021Revocation\": true}"
VENDOR_B_CREDENTIAL=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $VENDOR_B_CREDENTIAL | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential to node-B" 1>&2
  echo $VENDOR_B_CREDENTIAL
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $VENDOR_B_CREDENTIAL | curl -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/holder/vendorB/vc -H "Content-Type:application/json")
if echo $RESPONSE == ""; then
  echo "VC stored in wallet"
else
  echo "FAILED: Could not load NutsOrganizationCredential in node-B wallet" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Perform OAuth 2.0 JWT bearer flow..."
echo "---------------------------------------"
REQUEST=$(
cat << EOF
{
  "authorization_server": "https://nodeA/oauth2/vendorA",
  "scope": "test",
  "token_type": "bearer"
}
EOF
)
# Request access token using JWT bearer grant type (no DPoP)
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v2/vendorB/request-service-access-token -H "Content-Type: application/json")
if echo $RESPONSE | grep -q "access_token"; then
  ACCESS_TOKEN=$(echo $RESPONSE | sed -E 's/.*"access_token":"([^"]*).*/\1/')
  echo "access token obtained"
else
  echo "FAILED: Could not get access token from node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Introspect access token..."
echo "------------------------------------"
RESPONSE=$(curl -X POST -s --data "token=$ACCESS_TOKEN" http://localhost:18081/internal/auth/v2/accesstoken/introspect)
echo $RESPONSE
# Check that it contains "active": true
if echo $RESPONSE | grep -q "active.*true"; then
  echo "access token is active"
else
  echo "FAILED: Access token is not active" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
# Check that organization_name claim is present (from NutsOrganizationCredential)
if echo $RESPONSE | grep -q "organization_name"; then
  echo "organization_name claim is present"
else
  echo "FAILED: missing organization_name claim" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
# Verify JWT bearer was used: no presentation_submissions in introspect response
if echo $RESPONSE | grep -q "presentation_submissions"; then
  echo "FAILED: presentation_submissions should not be present for JWT bearer grant" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
else
  echo "JWT bearer confirmed: no presentation_submissions in token"
fi

echo "------------------------------------"
echo "Retrieving data..."
echo "------------------------------------"
RESPONSE=$($dc exec nodeB curl --http1.1 --insecure --cert /etc/nginx/ssl/server.pem --key /etc/nginx/ssl/key.pem https://nodeA:443/resource -H "Authorization: Bearer $ACCESS_TOKEN")
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
$dc down
