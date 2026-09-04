#!/usr/bin/env bash
USER=$UID

set -e

source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
# Empty node DIDs to avoid warning in Docker logs
export NODEA_DID=
export NODEB_DID=
export BOOTSTRAP_NODES=nodeA:5555
docker compose down
docker compose rm -f -v
rm -rf ./node-*/data

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
# 'data' dirs will be created with root owner by docker if they do not exist.
# This creates permission issues on CI, since we manually delete the network/connections.db file.
mkdir -p ./node-A/data/network ./node-B/data/network
docker compose up --wait

echo "------------------------------------"
echo "Creating NodeDIDs, waiting for Golden Hammer to register base URLs..."
echo "------------------------------------"
export NODEA_DID=$(setupNode "http://localhost:18081" "nodeA:5555")
printf "NodeDID for node A: %s\n" "$NODEA_DID"
waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 3 10 # 2 for setupNode, 1 for GoldenHammer
export NODEB_DID=$(setupNode "http://localhost:28081" "nodeB:5555")
printf "NodeDID for node B: %s\n" "$NODEB_DID"
waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 6 10 # 2 for setupNode, 1 for GoldenHammer

echo "------------------------------------"
echo "Restarting with NodeDID set..."
echo "------------------------------------"
# Start without bootstrap node, to enforce authenticated, discovered connections
export BOOTSTRAP_NODES=
docker compose exec nodeA-backend rm -f /opt/nuts/data/network/connections.db
docker compose exec nodeB-backend rm -f /opt/nuts/data/network/connections.db
docker compose stop
docker compose up --wait

echo "------------------------------------"
echo "Stopping node B, to simulate it being (temporarily) unreachable..."
echo "------------------------------------"
docker compose stop nodeB-backend nodeB

echo "------------------------------------"
echo "Issuing a credential while node B is down..."
echo "------------------------------------"
# The initial synchronous OpenID4VCI push fails (node B is unreachable), but issuing still succeeds
# immediately: the offer is queued for background retry instead of failing the request.
vcNodeA=$(createAuthCredential "http://localhost:18081" "$NODEA_DID" "$NODEB_DID")
printf "VC issued by node A (queued for retry): %s\n" "$vcNodeA"
if [ -z "$vcNodeA" ] || [ "$vcNodeA" == "null" ]; then
  echo "FAILED: issuing the credential while node B was down should still succeed immediately (queued for retry)"
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Bringing node B back up..."
echo "------------------------------------"
docker compose start nodeB-backend nodeB

echo "------------------------------------"
echo "Waiting for the queued credential to be delivered automatically..."
echo "------------------------------------"
# A longer, dedicated wait: node B needs to fully restart (migrations, etc.) *and* node A's
# background retry needs to fire again, on top of the fixed budget waitForDiagnostic gives elsewhere.
RETRY_TIMEOUT=60
retry=0
delivered=false
while [ $retry -lt $RETRY_TIMEOUT ]; do
  RESPONSE=$(curl -s "http://localhost:28081/status/diagnostics")
  if echo $RESPONSE | grep -q "credential_count: 1"; then
    delivered=true
    break
  fi
  printf "."
  sleep 1
  retry=$[$retry+1]
done
echo ""
if [ $delivered == false ]; then
  echo "FAILED: credential was not delivered to node B within ${RETRY_TIMEOUT}s of it coming back up"
  exitWithDockerLogs 1
fi

waitForDiagnostic "nodeA-backend" issued_credentials_count 1

# Now the credential should be present on both nodeA and nodeB
echo $(readCredential "http://localhost:18081" $vcNodeA)
echo $(readCredential "http://localhost:28081" $vcNodeA)

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
