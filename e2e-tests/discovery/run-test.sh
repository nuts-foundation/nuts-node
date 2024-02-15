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

REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${DID}\", \"credentialSubject\": {\"id\":\"${DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"withStatusList2021Revocation\": false}"
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
# Start Discovery Server
docker compose up --wait nodeA
# Registration refresh interval is 500ms, wait some to make sure the registration is refreshed
sleep 2

echo "---------------------------------------"
echo "Searching for care organization registration on Discovery Server..."
echo "---------------------------------------"
RESPONSE=$(curl -s --insecure "http://localhost:11323/internal/discovery/v1/dev:eOverdracht2023?credentialSubject.organization.name=Care*")
NUM_ITEMS=$(echo $RESPONSE | jq length)
if [ $NUM_ITEMS -eq 1 ]; then
  echo "Registration found"
else
  echo "FAILED: Could not find registration" 1>&2
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Searching for care organization registration on Discovery Client..."
echo "---------------------------------------"
# Service refresh interval is 500ms, wait some to make sure the presentations are loaded
sleep 2
RESPONSE=$(curl -s --insecure "http://localhost:21323/internal/discovery/v1/dev:eOverdracht2023?credentialSubject.organization.name=Care*")
NUM_ITEMS=$(echo $RESPONSE | jq length)
if [ $NUM_ITEMS -eq 1 ]; then
  echo "Registration found"
else
  echo "FAILED: Could not find registration" 1>&2
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
