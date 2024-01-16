#!/usr/bin/env bash
source ../util.sh

# This test asserts the following:
# - Clients update the Discovery Service
# - Clients can register presentations on the Discovery Service
# - When a presentation can't be registered on the Discovery Service, the client will retry
# - Clients can find presentations on the Discovery Service

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
docker compose up --wait nodeB

echo "------------------------------------"
echo "Registering care organization..."
echo "------------------------------------"
DIDDOC=$(docker compose exec nodeB nuts vdr create-did --v2)
DID=$(echo $DIDDOC | jq -r .id)
echo DID: $DID

REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${DID}\", \"credentialSubject\": {\"id\":\"${DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"publishToNetwork\": false}"
RESPONSE=$(echo $REQUEST | curl --insecure -s -X POST --data-binary @- http://localhost:21323/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $RESPONSE | curl --insecure -s -X POST --data-binary @- http://localhost:21323/internal/vcr/v2/holder/${DID}/vc -H "Content-Type:application/json")
if [$RESPONSE -eq ""]; then
  echo "VC stored in wallet"
else
  echo "FAILED: Could not load NutsOrganizationCredential" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Registering care organization on Discovery Service..."
echo "---------------------------------------"
curl --insecure -s -X POST http://localhost:21323/internal/discovery/v1/dev:eOverdracht2023/${DID}

echo "---------------------------------------"
echo "Restarting to force registration on Discovery Service..."
echo "---------------------------------------"
docker compose up --wait nodeA
docker compose down nodeB
docker compose up --wait nodeB

echo "---------------------------------------"
echo "Searching for care organization registration..."
echo "---------------------------------------"
echo "TODO: Requires clients updating discovery service and search API (https://github.com/nuts-foundation/nuts-node/pull/2672)"

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
