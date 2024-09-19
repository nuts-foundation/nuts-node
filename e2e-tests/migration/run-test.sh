#!/usr/bin/env bash
source ../util.sh
USER=$UID

# createOrg creates a DID under the control of another DID
# Args:     controller DID
# Returns:  the created DID
function createOrg() {
  printf '{
    "selfControl": false,
    "controllers": ["%s"],
    "assertionMethod": true,
    "capabilityInvocation": false
  }' "$1" | \
  curl -sS -X POST "http://localhost:18081/internal/vdr/v1/did" -H "Content-Type: application/json" --data-binary @- | jq -r ".id"
}

# addServiceV1 add a service to a DID document using the vdr/v1 API
# Args:     service host, service type, DID to add the service to
# Returns:  null
function addServiceV1() {
  printf '{
    "type": "%s",
    "endpoint": "%s/%s"
  }' "$2" "$1" "$2" | \
  curl -sS -X POST "http://localhost:18081/internal/didman/v1/did/$3/endpoint" -H "Content-Type: application/json" --data-binary @- > /dev/null
}

# addVerificationMethodV1 add a verification method to a DID document using the vdr/v1 API
# Args:     DID to add the verification method to
# Returns:  null
function addVerificationMethodV1() {
  curl -sS -X POST "http://localhost:18081/internal/vdr/v1/did/$1/verificationmethod" > /dev/null
}

# deactivateDIDV1 deactivates a DID document using the vdr/v1 API
# Args:     DID to deactivate
# Returns:  null
function deactivateDIDV1() {
  curl -sS -X DELETE "http://localhost:18081/internal/vdr/v1/did/$1" > /dev/null
}

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose -f docker-compose-pre-migration.yml down
docker compose -f docker-compose-pre-migration.yml rm -f -v
rm -rf ./node*/{data,backup}
mkdir ./nodeA/{data,backup}  ./nodeB/data  # 'data' dirs will be created with root owner by docker if they do not exit. This creates permission issues on CI.

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose -f docker-compose-pre-migration.yml up --wait nodeA nodeB

echo "------------------------------------"
echo "Registering DIDs..."
echo "------------------------------------"
# Register Vendor
VENDOR_DID=$(curl -X POST -sS http://localhost:18081/internal/vdr/v1/did | jq -r .id)
echo Vendor DID: "$VENDOR_DID"
# Register org1
ORG1_DID=$(createOrg "$VENDOR_DID")
echo Org1 DID: "$ORG1_DID"
# Register org2
ORG2_DID=$(createOrg "$VENDOR_DID")
echo Org2 DID: "$ORG2_DID"
# Register org3
ORG3_DID=$(createOrg "$VENDOR_DID")
echo Org3 DID: "$ORG3_DID"

# Wait for NodeB to contain 4 transactions
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 4 10

echo "------------------------------------"
echo "Making backup nodeA..."
echo "------------------------------------"
docker compose -f docker-compose-pre-migration.yml stop nodeA
cp -R ./nodeA/data/* ./nodeA/backup
docker compose -f docker-compose-pre-migration.yml up --wait nodeA

echo "------------------------------------"
echo "Adding and syncing left branch..."
echo "------------------------------------"
addServiceV1 "http://vendor" "service1" "$VENDOR_DID"
deactivateDIDV1 "$ORG2_DID"
addServiceV1 "http://org1" "service1" "$ORG1_DID"
addServiceV1 "http://org3" "service1" "$ORG3_DID"

# Wait for NodeB to contain 8 transactions
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 8 10

echo "------------------------------------"
echo "Restoring backup to nodeA..."
echo "------------------------------------"
docker compose -f docker-compose-pre-migration.yml stop
rm -r ./nodeA/data
mv ./nodeA/backup ./nodeA/data
docker compose -f docker-compose-pre-migration.yml up nodeA --wait nodeA

echo "------------------------------------"
echo "Adding right branch..."
echo "------------------------------------"
addServiceV1 "http://vendor" "service2" "$VENDOR_DID"
addServiceV1 "http://org1" "service2" "$ORG1_DID"
addServiceV1 "http://org2" "service2" "$ORG2_DID"
addVerificationMethodV1 "$ORG3_DID"

# Check NodeA contains 8 transactions, nodeB is offline
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 8 10

echo "------------------------------------"
echo "Syncing right branch..."
echo "------------------------------------"
docker compose -f docker-compose-pre-migration.yml up --wait nodeB

# Wait for NodeB to contain 12 transactions
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 12 10

echo "------------------------------------"
echo "Fix some DID document conflicts..."
echo "------------------------------------"
addVerificationMethodV1 "$VENDOR_DID"
addServiceV1 "http://org3" "service2" "$ORG3_DID"

# Wait for NodeB to contain 14 transactions
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 14 10

echo "------------------------------------"
echo "Upgrade nodeA to v6..."
echo "------------------------------------"
docker compose -f docker-compose-pre-migration.yml down
docker compose -f docker-compose-post-migration.yml up --wait nodeA nodeB

# Wait for NodeB to contain 16 transactions
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 16 10

echo "------------------------------------"
echo "Verifying migration results..."
echo "------------------------------------"
# TODO


echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose -f docker-compose-post-migration.yml stop
