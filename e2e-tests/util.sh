#!/usr/bin/env bash

function waitForTXCount {
  SERVICE_NAME=$1
  URL=$2
  TX_COUNT=$3
  TIMEOUT=$4
  printf "Waiting for service '%s' to contain %s transactions" $SERVICE_NAME $TX_COUNT
  done=false
  retry=0
  while [ $retry -lt $TIMEOUT ]; do

    RESPONSE=$(curl -s $URL)
    if echo $RESPONSE | grep -q "transaction_count: $TX_COUNT"; then
      done=true
      break
    fi

    printf "."
    sleep 1
    retry=$[$retry+1]
  done

  if [ $done == false ]; then
    printf "FAILED: Service '%s' did not get %d transaction within %d seconds" $SERVICE_NAME $TX_COUNT $TIMEOUT
    exitWithDockerLogs 1
  fi
  echo ""
}

# waitForDiagnostic waits for a Nuts node's diagnostic to display a certain value for a given key
# Args:    service name, key to check, expected value
function waitForDiagnostic {
  SERVICE_NAME=$1
  KEY=$2
  VALUE=$3
  TIMEOUT=10
  printf "Waiting for service '%s' diagnostic (%s: %s)" $SERVICE_NAME $KEY $VALUE
  done=false
  retry=0
  while [ $retry -lt $TIMEOUT ]; do
    RESPONSE=$(docker compose exec $SERVICE_NAME nuts status)
    if echo $RESPONSE | grep -q "${KEY}: ${VALUE}"; then
      done=true
      break
    fi

    printf "."
    sleep 1
    retry=$[$retry+1]
  done

  if [ $done == false ]; then
    echo "FAILED"
    exitWithDockerLogs 1
  fi
  echo ""
}

function exitWithDockerLogs {
  EXIT_CODE=$1
  docker compose logs
  docker compose down
  exit $EXIT_CODE
}

# waitForKeyPress waits for the enter key to be pressed
function waitForKeyPress() {
  read -p "Press enter to continue"
}

# setupNode creates a node's DID document and registers its NutsComm endpoint.
# Args:     node HTTP address, node gRPC address
# Returns:  the created DID
function setupNode() {
  local did=$(printf '{
    "selfControl": true,
    "keyAgreement": true,
    "assertionMethod": true,
    "capabilityInvocation": true
  }' | curl -s -X POST "$1/internal/vdr/v1/did" -H "Content-Type: application/json" --data-binary @- | jq -r ".id")

  printf '{
    "type": "NutsComm",
    "endpoint": "grpc://%s"
  }' "$2" | curl -s -X POST "$1/internal/didman/v1/did/$did/endpoint" -H "Content-Type: application/json" --data-binary @- > /dev/null

  echo "$did"
}

# assertDiagnostic checks whether a certain string appears on a node's diagnostics page.
# Args: node HTTP address, string to assert
function assertDiagnostic() {
  RESPONSE=$(curl -s "$1/status/diagnostics")
  if echo $RESPONSE | grep -q "${2}"; then
    echo "Diagnostics contains '${2}'"
  else
    echo "FAILED: diagnostics does not report '${2}'" 1>&2
    echo $RESPONSE
    exitWithDockerLogs 1
  fi
}

# readDiagnostic reads a specific value from the node's diagnostics page.
# Args: node HTTP address, key to read
function readDiagnostic() {
  # Given 'uptime'; read diagnostics, find line with 'uptime: ' and remove key + colon, print with stripped spaces
  local result=$(curl -s "$1/status/diagnostics" | grep "${2}:" | sed -e "s/$2://")
  if [[ $OSTYPE == 'darwin'* ]]; then
    # builtin sh on mac does not accept -n option, just prints it instead
    echo "${result//[[:space:]]/}"
  else
    echo -n "${result//[[:space:]]/}"
  fi
}

# createAuthCredential issues a NutsAuthorizationCredential
# Args:     issuing node HTTP address, issuer DID, subject DID
# Returns:  the VC ID
function createAuthCredential() {
  printf '{
    "type": "NutsAuthorizationCredential",
    "issuer": "%s",
    "credentialSubject": {
      "id": "%s",
      "resources": [],
      "purposeOfUse": "example",
      "subject": "urn:oid:2.16.840.1.113883.2.4.6.3:123456780"
    },
   "visibility": "private"
  }' "$2" "$3" | curl -s -X POST "$1/internal/vcr/v2/issuer/vc" -H "Content-Type: application/json" --data-binary @- | jq ".id" | sed "s/\"//g"
}

# registerStringService registers a service on a DID document, with a string as serviceEndpoint
# Args:   issuing node HTTP address, DID, service type, service endpoint
function registerStringService() {
    printf '{
      "type": "%s",
      "endpoint": "%s"
    }' "$3" "$4" | curl -s -X POST "$1/internal/didman/v1/did/$2/endpoint" -H "Content-Type: application/json" --data-binary @- > /dev/null
}

# readCredential resolves a VC
# Args:     node HTTP address, VC ID
# Returns:  the VC as JSON
function readCredential() {
  curl -s "$1/internal/vcr/v2/vc/${2//#/%23}"
}

# revokeCredential revokes a VC
# Args: node HTTP address, VC ID
function revokeCredential() {
  curl -s -X DELETE "$1/internal/vcr/v2/issuer/vc/${2//#/%23}"
}

# runOnAlpine runs the given command on a Alpine docker image
# Args: Docker volume mount (hostPath:dockerPath), remaining args are the command to run
function runOnAlpine() {
  # Say you have a folder './data/' that is used by the Nuts node, and you want to delete its contents.
  # Running 'rm -rf ./data/*' from the run-test.sh script will fail with permission issues.
  # This is due to github actions file permission issues explained in https://github.com/actions/runner/issues/691
  #
  # You can successfully delete the entire folder using:
  # runOnAlpine "$(pwd):/host/" rm -rf /host/data
  docker run --rm -v "$1" alpine "${@:2}"
}

# finds a node DID in the nuts.yaml on the provided path
function findNodeDID() {
  egrep -o 'nodedid:.*' $1 | awk '{print $2}'
}

# remove any node DID from the nuts.yaml on the provided path
function removeNodeDID() {
  if [[ $OSTYPE == 'darwin'* ]]; then
    # sed works different on MacOS; see https://stackoverflow.com/questions/19456518
    sed -i '' -e '/nodedid: did:nuts:/d' $1
  else
    sed -i '/nodedid: did:nuts:/d' $1
  fi
}
