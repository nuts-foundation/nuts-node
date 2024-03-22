#!/usr/bin/env bash
echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v
rm -rf ./node-*/data
mkdir ./node-A/data ./node-B/data  # 'data' dirs will be created with root owner by docker if they do not exit. This creates permission issues on CI.

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d --remove-orphans
docker compose up --wait nodeA nodeB

echo "------------------------------------"
echo "Registering DIDs..."
echo "------------------------------------"
# Register Party A
PARTY_A_DIDDOC=$(docker compose exec nodeA-backend nuts vdr create-did --v2)
PARTY_A_DID=$(echo $PARTY_A_DIDDOC | jq -r .id)
echo Party A DID: $PARTY_A_DID

# Register Vendor B
PARTY_B_DIDDOC=$(docker compose exec nodeB-backend nuts vdr create-did --v2)
PARTY_B_DID=$(echo $PARTY_B_DIDDOC | jq -r .id)
echo Party B DID: $PARTY_B_DID

./do-test.sh