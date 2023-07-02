#!/usr/bin/env bash

source ../../util.sh

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up --wait

echo "------------------------------------"
echo "Issuing private VCs..."
echo "------------------------------------"

nodeDID=$(findNodeDID "node-A/nuts.yaml")
printf "NodeDID for node A: %s\n" "$nodeDID"

unrevokedVC_ID=$(createAuthCredential "http://localhost:11323" "$nodeDID" "$nodeDID")
revokedVC_ID=$(createAuthCredential "http://localhost:11323" "$nodeDID" "$nodeDID")
revokeCredential "http://localhost:11323" "$revokedVC_ID"
assertDiagnostic "http://localhost:11323" "transaction_count: 5"
assertDiagnostic "http://localhost:11323" "credential_count: 2"
assertDiagnostic "http://localhost:11323" "issued_credentials_count: 2"
assertDiagnostic "http://localhost:11323" "revocations_count: 1"
DAG_XOR=$(readDiagnostic "http://localhost:11323" dag_xor)
unrevokedVC=$(readCredential "http://localhost:11323" "${unrevokedVC_ID}")

echo "------------------------------------"
echo "Making backups, then start with empty node..."
echo "------------------------------------"
sleep 1 # BBolt backup is made every second
echo "Making backups and removing node data"
docker compose stop
# Copy files not in BBolt DB, so they can be restored. Then empty data dir.
cp ./node-data/vcr/trusted_issuers.yaml ./node-backup/vcr/
cp -r ./node-data/crypto ./node-backup
runOnAlpine "$(pwd):/host/" rm -rf /host/node-data
mkdir ./node-data
removeNodeDID ./node-A/nuts.yaml
# Restart node, assert node data is empty
echo "Asserting node is empty"
BACKUP_INTERVAL=0 docker compose up --wait
assertDiagnostic "http://localhost:11323" "transaction_count: 0"
assertDiagnostic "http://localhost:11323" "credential_count: 0"
# Restore data and rebuild
echo "Restoring node data"
docker compose stop
runOnAlpine "$(pwd):/host/" rm -rf /host/node-data
runOnAlpine "$(pwd):/host/" mv -f /host/node-backup /host/node-data
BACKUP_INTERVAL=0 docker compose up --wait

echo "Rebuilding data"
docker compose exec nodeA nuts network reprocess "application/vc+json"
docker compose exec nodeA nuts network reprocess "application/ld+json;type=revocation"

# Wait for some time for reprocess to finish
sleep 5

assertDiagnostic "http://localhost:11323" "transaction_count: 5"
assertDiagnostic "http://localhost:11323" "credential_count: 2"
assertDiagnostic "http://localhost:11323" "issued_credentials_count: 2"
assertDiagnostic "http://localhost:11323" "revoked_credentials_count: 1"
assertDiagnostic "http://localhost:11323" "revocations_count: 1"
assertDiagnostic "http://localhost:11323" "dag_xor: ${DAG_XOR}"
# Read VC and check its the same after restore
unrevokedVCAfterRestore=$(readCredential "http://localhost:11323" "${unrevokedVC_ID}")
if [ "${unrevokedVC}" != "${unrevokedVCAfterRestore}" ]; then
  echo "FAILED: VC is differs after restore"
  exit 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop