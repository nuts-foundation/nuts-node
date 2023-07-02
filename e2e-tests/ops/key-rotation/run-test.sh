#!/usr/bin/env bash

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up --wait

# Test description:
#  Node A:
#    1. create DID,
#    2. add verification method (should be signed with current, old key),
#    3. remove old key (should be signed with new key),
#    4. add service (should be signed with new key)
#  Node B:
#    5. resolve DID,
#    6. assert old key is not present in latest version,
#    7. assert new key is present
#    8. assert new service is present

echo "------------------------------------"
echo "Creating DID and performing key rotation..."
echo "------------------------------------"
# Register DID
DIDDOC=$(docker compose exec nodeA nuts vdr create-did)
DID=$(echo $DIDDOC | jq -r .id)
FIRST_VM_ID=$(echo $DIDDOC | jq -r ".verificationMethod[0].id")
echo "DID: ${DID}"
echo "First Verification Method ID: ${FIRST_VM_ID}"

# Add verification method
VM=$(docker compose exec nodeA nuts vdr addvm $DID)
SECOND_VM_ID=$(echo $VM | jq -r ".id")
echo "New Verification Method ID: ${SECOND_VM_ID}"

# Remove old verification method
docker compose exec nodeA nuts vdr delvm $DID $FIRST_VM_ID

# Register service
docker compose exec nodeA nuts didman svc add $DID "MotD", "Hello, World!"

echo "------------------------------------"
echo "Assert DID document on other node..."
echo "------------------------------------"
# Wait for Nuts Network nodes to sync
sleep 2

DIDDOC_RESOLVED=$(docker compose exec nodeB nuts vdr resolve "${DID}")

if [[ "${DIDDOC_RESOLVED}" != *"MotD"* ]]; then
  echo "failed to find last DID document version from node A"
  exitWithDockerLogs 1
fi
echo OK: Found last DID document version

if [[ "${DIDDOC_RESOLVED}" != *"${SECOND_VM_ID}"* ]]; then
  echo "failed to find new key on DID document from node A"
  exitWithDockerLogs 1
fi
echo OK: Found new key on DID document

if [[ "${DIDDOC_RESOLVED}" == *"${FIRST_VM_ID}"* ]]; then
  echo "failed: found find old key on DID document from node A, which should have been removed"
  exitWithDockerLogs 1
fi
echo OK: Old key not present any more on DID document

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
