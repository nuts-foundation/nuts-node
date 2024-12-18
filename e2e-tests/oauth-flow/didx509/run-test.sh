#!/usr/bin/env bash
source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down --remove-orphans
docker compose rm -f -v

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d
docker compose up --wait nodeA nodeA-backend

echo "------------------------------------"
echo "Registering vendors..."
echo "------------------------------------"
# Register Vendor A
REQUEST="{\"subject\":\"vendorA\"}"
VENDOR_A_DIDDOC=$(echo $REQUEST | curl -X POST --data-binary @- http://localhost:18081/internal/vdr/v2/subject --header "Content-Type: application/json")
VENDOR_A_DID=$(echo $VENDOR_A_DIDDOC | jq -r .documents[0].id)
echo Vendor A DID: $VENDOR_A_DID

echo "------------------------------------"
echo "Issuing X509Credential..."
echo "------------------------------------"
CREDENTIAL=$(docker run \
  -v "$(pwd)/certs/nodeA-chain.pem:/cert-chain.pem:ro" \
  -v "$(pwd)/certs/nodeA.key:/cert-key.key:ro" \
  reinkrul/uzi-did-x509-issuer:latest \
  vc "/cert-chain.pem" "/cert-key.key" "${VENDOR_A_DID}")
echo $CREDENTIAL

RESPONSE=$(echo "\"${CREDENTIAL}\"" | curl -s -o /dev/null -w "%{http_code}" -X POST --data-binary @- http://localhost:18081/internal/vcr/v2/holder/vendorA/vc -H "Content-Type:application/json")
if [ $RESPONSE -eq 204 ]; then
  echo "VC stored in wallet"
else
  echo "FAILED: Could not load X509Credential in wallet" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# Register on Discovery Service
echo "Registering on Discovery Service..."
REQUEST="{\"registrationParameters\":{\"key\":\"value\"}}"
RESPONSE=$(echo $REQUEST | curl -s -o /dev/null -w "%{http_code}" -X POST --data-binary @- http://localhost:18081/internal/discovery/v1/e2e-test/vendorA)
if [ $RESPONSE -eq 200 ]; then
  echo "Registered on Discovery Service"
else
  echo "FAILED: Could not register on Discovery Service" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "Searching for registration on Discovery Service..."
RESPONSE=$(curl -s --insecure http://localhost:18081/internal/discovery/v1/e2e-test?credentialSubject.O=Because*)
NUM_ITEMS=$(echo $RESPONSE | jq length)
if [ $NUM_ITEMS -eq 1 ]; then
  echo "Registration found"
else
  echo "FAILED: Could not find registration" 1>&2
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Perform OAuth 2.0 rfc021 flow..."
echo "---------------------------------------"
REQUEST=$(
cat << EOF
{
  "authorization_server": "https://nodeA/oauth2/vendorA",
  "token_type": "bearer",
  "scope": "test"
}
EOF
)
# Request access token
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:18081/internal/auth/v2/vendorA/request-service-access-token -H "Content-Type: application/json")
if echo $RESPONSE | grep -q "access_token"; then
  ACCESS_TOKEN=$(echo $RESPONSE | jq -r .access_token)
else
  echo "FAILED: Could not get access token from node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
echo Access token: $ACCESS_TOKEN

echo "------------------------------------"
echo "Introspect access token..."
echo "------------------------------------"
RESPONSE=$(curl -X POST -s --data "token=$ACCESS_TOKEN" http://localhost:18081/internal/auth/v2/accesstoken/introspect)
echo Introspection response: $RESPONSE

# Check that it contains the following claims:
# - "organization_ura":"00001"
# - "organization_name":"Because We Care"
# - "organization_city":"Healthland"
if [ "$(echo $RESPONSE | jq -r .organization_ura)" != "00001" ]; then
  echo "FAILED: organization_ura claim not found" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

if [ "$(echo $RESPONSE | jq -r .organization_name)" != "Because We Care" ]; then
  echo "FAILED: organization_name claim not found" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

if [ "$(echo $RESPONSE | jq -r .organization_city)" != "Healthland" ]; then
  echo "FAILED: organization_city claim not found" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose down