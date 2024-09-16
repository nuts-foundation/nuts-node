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
docker compose up --wait nodeA

echo "------------------------------------"
echo "Registering vendors..."
echo "------------------------------------"

# Create Subject
DID_DOCS=$(curl -s -X POST http://localhost:18081/internal/vdr/v2/subject)
# Get @context at index 0 from all DID Documents
FIRST_CONTEXT=$(echo ${DID_DOCS} | jq -r '.documents[]["@context"][0]')
COUNTER=0
for row in ${FIRST_CONTEXT}; do
  if [ "$row" != "https://www.w3.org/ns/did/v1" ]; then
    FAILING_DID=$(echo ${DID_DOCS} | jq -r ".documents[${COUNTER}].id")
    echo "First Context in DID Document '${FAILING_DID}' ($row) is not equal to https://www.w3.org/ns/did/v1"
    echo ${DID_DOCS} | jq -r .documents[${COUNTER}]
    docker compose stop
    exit 1
  fi
  COUNTER=$((COUNTER + 1))
done

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
