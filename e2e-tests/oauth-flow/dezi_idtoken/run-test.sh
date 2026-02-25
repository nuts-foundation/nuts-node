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
  --rm \
  -v "$(pwd)/certs/nodeA-chain.pem:/cert-chain.pem:ro" \
  -v "$(pwd)/certs/nodeA.key:/cert-key.key:ro" \
  nutsfoundation/go-didx509-toolkit:main \
  vc "/cert-chain.pem" "/cert-key.key" "CN=Fake UZI Root CA" "${VENDOR_A_DID}")

RESPONSE=$(echo "\"${CREDENTIAL}\"" | curl -s -o /dev/null -w "%{http_code}" -X POST --data-binary @- http://localhost:18081/internal/vcr/v2/holder/vendorA/vc -H "Content-Type:application/json")
if [ $RESPONSE -eq 204 ]; then
  echo "VC stored in wallet"
else
  echo "FAILED: Could not load X509Credential in wallet" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Perform OAuth 2.0 rfc021 flow..."
echo "---------------------------------------"

# Run generate-jwt.sh, and read the input into a var, clean newlines
IDTOKEN=$(./generate-jwt.sh | tr -d '\n')

REQUEST=$(
cat << EOF
{
  "authorization_server": "https://nodeA/oauth2/vendorA",
  "token_type": "bearer",
  "scope": "test",
  "id_token": "$IDTOKEN"
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
# - "organization_ura_dezi":"87654321"
# - "user_initials":"B.B."
# - "user_roles":["01.041","30.000","01.010","01.011"]
# - "user_surname":"Jansen"
# - "user_surname_prefix":"van der"
# - "user_uzi":"900000009"
if [ "$(echo $RESPONSE | jq -r .organization_ura_dezi)" != "87654321" ]; then
  echo "FAILED: organization_ura_dezi invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
if [ "$(echo $RESPONSE | jq -r .user_initials)" != "B.B." ]; then
  echo "FAILED: user_initials invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
USER_ROLES=$(echo $RESPONSE | jq -r '.user_roles | sort | join(",")')
if [ "$USER_ROLES" != "01.010,01.011,01.041,30.000" ]; then
  echo "FAILED: user_roles invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
if [ "$(echo $RESPONSE | jq -r .user_surname)" != "Jansen" ]; then
  echo "FAILED: user_surname invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
if [ "$(echo $RESPONSE | jq -r .user_surname_prefix)" != "van der" ]; then
  echo "FAILED: user_surname_prefix invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
if [ "$(echo $RESPONSE | jq -r .user_uzi)" != "900000009" ]; then
  echo "FAILED: user_uzi invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose down