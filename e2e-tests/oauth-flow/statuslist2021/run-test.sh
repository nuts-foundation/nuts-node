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
docker compose up -d --remove-orphans
docker compose up --wait nodeA nodeB

echo "------------------------------------"
echo "Registering vendors..."
echo "------------------------------------"

# Register Party A
PARTY_A_DIDDOC=$(curl -s -X POST http://localhost:18081/internal/vdr/v2/subject)
PARTY_A_DID=$(echo $PARTY_A_DIDDOC | jq -r .documents[0].id)
echo "  Vendor A DID: $PARTY_A_DID"

# Register Vendor B
PARTY_B_DIDDOC=$(curl -s -X POST http://localhost:28081/internal/vdr/v2/subject)
PARTY_B_DID=$(echo $PARTY_B_DIDDOC | jq -r .documents[0].id)
echo "  Vendor B DID: $PARTY_B_DID"

echo "---------------------------------------"
echo "Issuing NutsOrganizationCredential..."
echo "---------------------------------------"

# Issue NutsOrganizationCredential for Vendor B with a revocable StatusList2021Entry in VC.credentialStatus
REQUEST="{\"@context\":[\"https://www.w3.org/2018/credentials/v1\", \"https://nuts.nl/credentials/v1\"], \"type\":\"NutsOrganizationCredential\", \"issuer\":\"${PARTY_B_DID}\", \"credentialSubject\": {\"id\":\"${PARTY_B_DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"withStatusList2021Revocation\": true}"
RESPONSE=$(echo $REQUEST | curl -s -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  CREDENTIAL_ID=$( echo $RESPONSE | jq .id  | sed "s/\"//g" )
  echo "  VC issued: $CREDENTIAL_ID"
else
  echo "  FAILED: Could not issue NutsOrganizationCredential to node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

VALIDATION_REQUEST="{\"verifiableCredential\": ${RESPONSE}}"

echo "---------------------------------------"
echo "Validating credential pt 1..."
echo "---------------------------------------"

RESPONSE=$(echo $VALIDATION_REQUEST | curl -s -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/verifier/vc -H "Content-Type:application/json")
if [[ $( echo $RESPONSE | jq -r .validity ) ==  "true" ]]; then
  echo "  VC considered valid by node-B"
else
  echo "  FAILED: Could not validate NutsOrganizationCredential in node-B wallet" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $VALIDATION_REQUEST | curl -s -X POST --data-binary @- http://localhost:18081/internal/vcr/v2/verifier/vc -H "Content-Type:application/json")
if [[ $( echo $RESPONSE | jq -r .validity ) ==  "true" ]]; then
  echo "  VC considered valid by node-A"
else
  echo "  FAILED: Could not validate NutsOrganizationCredential in node-A wallet" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Revoking NutsOrganizationCredential..."
echo "---------------------------------------"

revokeCredential "http://localhost:28081" "${CREDENTIAL_ID}"

echo "---------------------------------------"
echo "Validating credential pt 2..."
echo "---------------------------------------"

# confirm revoked by StatusList2021Credential on node-B, uses internal store
RESPONSE=$(echo $VALIDATION_REQUEST | curl -s -X POST --data-binary @- http://localhost:28081/internal/vcr/v2/verifier/vc -H "Content-Type:application/json")
echo nodeB response: $RESPONSE
if [[ $( echo $RESPONSE | jq -r .message ) ==  *"credential is revoked" ]]; then
  echo "  VC considered revoked by node-B"
else
  echo "  FAILED: Credential not revoked on node-B" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

# confirm revoked by StatusList2021Credential on node-A, fetches StatusList2021Credential from node-B using APIs
RESPONSE=$(echo $VALIDATION_REQUEST | curl -s -X POST --data-binary @- http://localhost:18081/internal/vcr/v2/verifier/vc -H "Content-Type:application/json")
echo nodeA response: $RESPONSE
if [[ $( echo $RESPONSE | jq -r .message ) ==  *"credential is revoked" ]]; then
  echo "  VC considered revoked by node-A"
else
  echo "  FAILED: Credential not revoked on node-A" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
