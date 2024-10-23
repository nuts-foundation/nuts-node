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

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up --wait nodeA-backend nodeA nodeB-backend nodeB

echo "------------------------------------"
echo "Registering care organization..."
echo "------------------------------------"
RESPONSE=$(curl --insecure -s -X POST http://localhost:28081/internal/vdr/v2/subject -H "Content-Type:application/json")
SUBJECT=$(echo $RESPONSE | jq -r .subject)
echo SUBJECT: $SUBJECT
DID=$(echo $RESPONSE | jq -r .documents[0].id)
echo DID: $DID

REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${DID}\", \"credentialSubject\": {\"id\":\"${DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"withStatusList2021Revocation\": false}"
RESPONSE=$(echo $REQUEST | curl --insecure -s -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $RESPONSE | curl --insecure -s -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/holder/${SUBJECT}/vc -H "Content-Type:application/json")
if [[ $RESPONSE -eq "" ]]; then
  echo "VC stored in wallet"
else
  echo "FAILED: Could not load NutsOrganizationCredential" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Registering care organization on Discovery Service..."
echo "---------------------------------------"
RESPONSE=$(curl --insecure -s -X POST http://localhost:28081/internal/discovery/v1/dev:eOverdracht2023/${SUBJECT})
if [ -z "${RESPONSE}" ]; then
  echo "Registered for service"
else
  echo "FAILED: Could not register for Discovery Service" 1>&2
  exitWithDockerLogs 1
fi

# Registration refresh interval is 500ms, wait some to make sure the registration is refreshed
sleep 2

echo "---------------------------------------"
echo "Searching for care organization registration on Discovery Server..."
echo "---------------------------------------"
RESPONSE=$(curl -s --insecure "http://localhost:18081/internal/discovery/v1/dev:eOverdracht2023?credentialSubject.organization.name=Care*&credentialSubject.organization.city=*")
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
RESPONSE=$(curl -s --insecure "http://localhost:28081/internal/discovery/v1/dev:eOverdracht2023?credentialSubject.organization.name=Care*")
NUM_ITEMS=$(echo $RESPONSE | jq length)
if [ $NUM_ITEMS -eq 1 ]; then
  echo "Registration found"
else
  echo "FAILED: Could not find registration" 1>&2
  exitWithDockerLogs 1
fi

if echo $RESPONSE | grep -q "authServerURL"; then
  echo "Authorization server URL found"
else
  echo "FAILED: Could not find authServerURL" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Retract Discovery Service registration..."
echo "---------------------------------------"
RESPONSE=$(curl --insecure -s -X DELETE http://localhost:28081/internal/discovery/v1/dev:eOverdracht2023/${SUBJECT})
if [ -z "${RESPONSE}" ]; then
  echo "Registration revoked"
else
  echo "FAILED: Registration not (immediately) revoked" 1>&2
  exitWithDockerLogs 1
fi

# Registration refresh interval is 500ms, wait some to make sure the registration is refreshed
sleep 2

echo "---------------------------------------"
echo "Searching for care organization registration on Discovery Server..."
echo "---------------------------------------"
RESPONSE=$(curl -s --insecure "http://localhost:18081/internal/discovery/v1/dev:eOverdracht2023?credentialSubject.organization.name=Care*")
NUM_ITEMS=$(echo $RESPONSE | jq length)
if [ $NUM_ITEMS -eq 0 ]; then
  echo "Registration not found"
else
  echo "FAILED: Found registration" 1>&2
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Searching for care organization registration on Discovery Client..."
echo "---------------------------------------"
RESPONSE=$(curl -s --insecure "http://localhost:28081/internal/discovery/v1/dev:eOverdracht2023?credentialSubject.organization.name=Care*")
NUM_ITEMS=$(echo $RESPONSE | jq length)
if [ $NUM_ITEMS -eq 0 ]; then
  echo "Registration not found"
else
  echo "FAILED: Found registration" 1>&2
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
