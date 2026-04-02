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

# Check that it contains the following claims from the Dezi token:
# Token contains:
# - "abonnee_nummer":"90000380" -> organization_ura_dezi
# - "dezi_nummer":"900022159" -> user_uzi
# - "voorletters":"J." -> user_initials
# - "achternaam":"90017362" -> user_surname
# - "voorvoegsel":null -> user_surname_prefix (empty)
# - "rol_code":"92.000" -> user_role
if [ "$(echo $RESPONSE | jq -r .organization_ura_dezi)" != "90000380" ]; then
  echo "FAILED: organization_ura_dezi invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
if [ "$(echo $RESPONSE | jq -r .user_initials)" != "J." ]; then
  echo "FAILED: user_initials invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
if [ "$(echo $RESPONSE | jq -r .user_role)" != "92.000" ]; then
  echo "FAILED: user_role invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
if [ "$(echo $RESPONSE | jq -r .user_surname)" != "90017362" ]; then
  echo "FAILED: user_surname invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
# voorvoegsel is null in the token, so user_surname_prefix should be empty or not present
USER_SURNAME_PREFIX=$(echo $RESPONSE | jq -r .user_surname_prefix)
if [ "$USER_SURNAME_PREFIX" != "" ] && [ "$USER_SURNAME_PREFIX" != "null" ]; then
  echo "FAILED: user_surname_prefix should be empty, got: $USER_SURNAME_PREFIX" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
if [ "$(echo $RESPONSE | jq -r .user_uzi)" != "900022159" ]; then
  echo "FAILED: user_uzi invalid" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose down