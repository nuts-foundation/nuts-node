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
# --remove-orphans to ensure that DB containers of previous runs (on e.g. Postgres) are removed when testing with SQLite.
# Nothing breaks otherwise, but it prevents annoying warnings in the log.
$db_dc down --remove-orphans
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

# Test regression for https://github.com/nuts-foundation/nuts-node/issues/3451
# (VCR: Status List can't be retrieved when using MS SQL Server)
# Get credential status URL from credentialStatus.statusListCredential property using jq
STATUS_LIST_CREDENTIAL=$(echo $VENDOR_B_CREDENTIAL | jq -r .credentialStatus.statusListCredential)
echo "Status list credential: $STATUS_LIST_CREDENTIAL"
# Get status list credential
RESPONSE=$($db_dc exec nodeB-backend curl -s -k $STATUS_LIST_CREDENTIAL)
# Check response HTTP 200 OK
if  echo $RESPONSE | grep -q "\"id\":\"$STATUS_LIST_CREDENTIAL\"" ; then
  echo "Status list credential retrieved"
else
  echo "FAILED: Could not retrieve status list credential" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# Register vendor B on Discovery Service
echo "Registering vendor B on Discovery Service..."
REQUEST="{\"registrationParameters\":{\"key\":\"value\"}}"
RESPONSE=$(echo $REQUEST | curl -s -o /dev/null -w "%{http_code}" -X POST --data-binary @- http://localhost:28081/internal/discovery/v1/e2e-test/vendorB)
if [ $RESPONSE -eq 200 ]; then
  echo "Vendor B registered on Discovery Service"
else
  echo "FAILED: Could not register vendor B on Discovery Service" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# Test regression for https://github.com/nuts-foundation/nuts-node/issues/3442
# (Discovery: GetActivationStatus fails on MS SQL Server)
echo "Getting activation status from Discovery Service..."
RESPONSE=$(curl -s http://localhost:28081/internal/discovery/v1/e2e-test/vendorB)
echo $RESPONSE
if echo $RESPONSE | grep -q "true"; then
  echo "Activation status OK"
else
  echo "FAILED: Could not get activation status of vendor B on Discovery Service" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# Search for registration using wildcards, results in complicated DB query
RESPONSE=$(curl -s --insecure http://localhost:28081/internal/discovery/v1/e2e-test?credentialSubject.organization.name=*)
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
  "scope": "test",
  "credentials": [
      {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://nuts.nl/credentials/v1"
        ],
        "type": ["VerifiableCredential", "NutsEmployeeCredential"],
        "credentialSubject": {
          "name": "John Doe",
          "roleName": "Janitor",
          "identifier": "123456"
        }
      }
    ]
}
EOF
)
# Request access token
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v2/vendorB/request-service-access-token -H "Content-Type: application/json")
if echo $RESPONSE | grep -q "access_token"; then
  echo $RESPONSE | sed -E 's/.*"access_token":"([^"]*).*/\1/' > ./node-B/accesstoken.txt
  echo "access token stored in ./node-B/accesstoken.txt"
else
  echo "FAILED: Could not get access token from node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi
DPOP_KID=$(echo $RESPONSE | sed -E 's/.*"dpop_kid":"([^"]*).*/\1/')
DPOP_KID=$(urlencode $DPOP_KID)
ACCESS_TOKEN=$(cat ./node-B/accesstoken.txt)

echo "------------------------------------"
echo "Create DPoP header..."
echo "------------------------------------"
REQUEST="{\"htm\":\"GET\",\"htu\":\"https://nodeA:443/resource\", \"token\":\"$ACCESS_TOKEN\"}"
RESPONSE=$(echo $REQUEST | curl -X POST -s --data-binary @- http://localhost:28081/internal/auth/v2/dpop/$DPOP_KID -H "Content-Type: application/json")
if echo $RESPONSE | grep -q "dpop"; then
  echo $RESPONSE | sed -E 's/.*"dpop":"([^"]*).*/\1/' > ./node-B/dpop.txt
  echo "dpop token stored in ./node-B/dpop.txt"
else
  echo "FAILED: Could not get dpop token from node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

DPOP=$(cat ./node-B/dpop.txt)

# Introspect access token with a form post
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
# Check that it contains "employee_name":"John Doe"
if echo $RESPONSE | grep -q "employee_name.*John Doe"; then
  echo "employee_name claim is present"
else
  echo "FAILED: missing/invalid employee_name" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Retrieving data..."
echo "------------------------------------"
RESPONSE=$($db_dc exec nodeB curl --http1.1 --insecure --cert /etc/nginx/ssl/server.pem --key /etc/nginx/ssl/key.pem https://nodeA:443/resource -H "Authorization: DPoP $ACCESS_TOKEN" -H "DPoP: $DPOP")
if echo $RESPONSE | grep -q "OK"; then
  echo "success!"
else
  echo "FAILED: Could not get resource from node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Revoking credential..."
echo "------------------------------------"
# revoke credential
VENDOR_B_CREDENTIAL_ID=$(echo $VENDOR_B_CREDENTIAL | jq -r .id)
echo $VENDOR_B_CREDENTIAL_ID
RESPONSE=$(curl -s -X DELETE "http://localhost:28081/internal/vcr/v2/issuer/vc/${VENDOR_B_CREDENTIAL_ID//#/%23}")
if [ -z "${RESPONSE}" ]; then
  echo "VendorB NutsOrganizationCredential revoked"
else
  echo "FAILED: NutsOrganizationCredential not revoked" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Retrieving data fails..."
echo "------------------------------------"
RESPONSE=$($db_dc exec nodeB curl --http1.1 --insecure --cert /etc/nginx/ssl/server.pem --key /etc/nginx/ssl/key.pem https://nodeA:443/resource -H "Authorization: DPoP $ACCESS_TOKEN" -H "DPoP: $DPOP")
if [ "${RESPONSE}" == "Unauthorized" ]; then
  echo "Access denied!"
else
  echo "FAILED: Retrieved data with revoked credential" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
$db_dc down
rm node-*/*.txt