#!/usr/bin/env bash

# Runs the Nuts network with the key-value stores (DAG, DID store, notifier jobs, credential backups) on SQL
# (storage.kv.backend=sql) instead of bbolt, once per supported database: SQLite, PostgreSQL, MySQL and SQL Server.
# Each variant: two nodes with their own database that start on bbolt, create public DID transactions, are switched
# to storage.kv.backend=sql (importing the bbolt data), then exchange private credentials (payload retrieval over
# authenticated connections, notifier jobs) and revocations, and are restarted to prove the data lives in SQL.

set -e

USER=$UID

source ../../util.sh

function searchAuthCredentials() {
  printf '{
    "query": {
      "@context": ["https://www.w3.org/2018/credentials/v1", "https://nuts.nl/credentials/v1"],
      "type": ["VerifiableCredential" ,"NutsAuthorizationCredential"],
      "credentialSubject": {
        "subject": "urn:oid:2.16.840.1.113883.2.4.6.3:123456780"
      }
    },
    "searchOptions": {
       "allowUntrustedIssuer": true
    }
  }' | curl -s -X POST "$1/internal/vcr/v2/search" -H "Content-Type: application/json" --data-binary @-
}

# Args: service name, node URL, expected number of credentials, timeout in seconds
function waitForAuthCredentialCount() {
  local service_name=$1
  local url=$2
  local expected=$3
  local timeout=$4
  local count=""
  printf "Waiting for service '%s' to return %s NutsAuthorizationCredentials" "$service_name" "$expected"
  local retry=0
  while [ $retry -lt $timeout ]; do
    count=$(searchAuthCredentials "$url" | jq ".verifiableCredentials | length")
    if [ "$count" == "$expected" ]; then
      echo ""
      return 0
    fi
    printf "."
    sleep 1
    retry=$((retry+1))
  done
  echo ""
  echo "FAILED: Service '$service_name' returned ${count:-no} NutsAuthorizationCredentials after ${timeout} seconds, expected $expected"
  exitWithDockerLogs 1
}

# assertBBoltMigrated fails when a node still has active bbolt files for the did:nuts stores, or lacks the renamed
# ".db.migrated" files that the import leaves behind.
# Args: compose service name
function assertBBoltMigrated() {
  # Only the go-leia index files may remain as .db in vcr/ (credentials.db, issued-credentials.db, verifier-store.db);
  # the backup-*.db KV stores must have been imported like network/ and vdr/.
  if docker compose exec "$1" sh -c 'ls /opt/nuts/data/network/*.db /opt/nuts/data/vdr/*.db /opt/nuts/data/vcr/backup-*.db 2>/dev/null' | grep -q .; then
    echo "FAILED: $1 still has active bbolt KV files in its data directory while storage.kv.backend=sql"
    docker compose exec "$1" sh -c 'ls -la /opt/nuts/data/network /opt/nuts/data/vdr /opt/nuts/data/vcr'
    exitWithDockerLogs 1
  fi
  if ! docker compose exec "$1" sh -c 'test -f /opt/nuts/data/network/data.db.migrated && test -f /opt/nuts/data/vdr/didstore.db.migrated && test -f /opt/nuts/data/vcr/backup-credentials.db.migrated'; then
    echo "FAILED: $1 has no .db.migrated files; the bbolt import did not run"
    docker compose exec "$1" sh -c 'ls -la /opt/nuts/data/network /opt/nuts/data/vdr /opt/nuts/data/vcr'
    exitWithDockerLogs 1
  fi
  echo "$1: bbolt stores imported into SQL and files renamed"
}

# startDatabase starts the database service for the variant (if any) and makes sure both node databases exist.
# Args: variant (sqlite|postgres|mysql|sqlserver)
function startDatabase() {
  case "$1" in
    sqlite)
      export NODE_A_SQL="sqlite:file:/opt/nuts/data/sqlite.db?_pragma=foreign_keys(1)&journal_mode(WAL)"
      export NODE_B_SQL="sqlite:file:/opt/nuts/data/sqlite.db?_pragma=foreign_keys(1)&journal_mode(WAL)"
      ;;
    postgres)
      docker compose --profile postgres up --wait postgres || exitWithDockerLogs 1
      export NODE_A_SQL="postgres://nuts:nuts@postgres:5432/nodea?sslmode=disable"
      export NODE_B_SQL="postgres://nuts:nuts@postgres:5432/nodeb?sslmode=disable"
      ;;
    mysql)
      docker compose --profile mysql up --wait mysql || exitWithDockerLogs 1
      export NODE_A_SQL="mysql://root:nuts@tcp(mysql:3306)/nodea?charset=utf8mb4&parseTime=True&loc=Local"
      export NODE_B_SQL="mysql://root:nuts@tcp(mysql:3306)/nodeb?charset=utf8mb4&parseTime=True&loc=Local"
      ;;
    sqlserver)
      docker compose --profile sqlserver up --wait sqlserver || exitWithDockerLogs 1
      # SQL Server has no init-script hook; create the databases through sqlcmd.
      docker compose exec sqlserver /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P 'Nuts!Passw0rd' \
        -Q "IF DB_ID('nodea') IS NULL CREATE DATABASE nodea; IF DB_ID('nodeb') IS NULL CREATE DATABASE nodeb;"
      export NODE_A_SQL="sqlserver://sa:Nuts!Passw0rd@sqlserver:1433?database=nodea"
      export NODE_B_SQL="sqlserver://sa:Nuts!Passw0rd@sqlserver:1433?database=nodeb"
      ;;
    *)
      echo "unknown database variant: $1"
      exit 1
      ;;
  esac
}

function runVariant() {
  local variant=$1
  echo "===================================="
  echo "Database: $variant"
  echo "===================================="

  echo "------------------------------------"
  echo "Cleaning up running Docker containers and volumes, and key material..."
  echo "------------------------------------"
  export NODE_A_DID=
  export NODE_B_DID=
  export NODE_A_SQL=
  export NODE_B_SQL=
  export BOOTSTRAP_NODES=nodeA:5555
  # Phase 1 runs without discovery: node A would otherwise dial node B's NutsComm address before node B has its
  # node DID, which fails fatally and persists a 24h backoff for node B. The private-transactions test deletes the
  # bbolt file holding that backoff between phases; on SQL there is no file, so the attempt is avoided instead.
  export ENABLE_DISCOVERY=false
  # Phase 1 runs on bbolt; the switch to sql (and the import of the bbolt data) happens at the first restart.
  export KV_BACKEND=bbolt
  docker compose --profile '*' down -v --remove-orphans
  rm -rf ./node-*/data
  # 'data' dirs will be created with root owner by docker if they do not exist.
  mkdir -p ./node-A/data ./node-B/data

  echo "------------------------------------"
  echo "Starting database..."
  echo "------------------------------------"
  startDatabase "$variant"

  echo "------------------------------------"
  echo "Starting nodes on bbolt..."
  echo "------------------------------------"
  docker compose up --wait nodeA nodeB || exitWithDockerLogs 1

  echo "------------------------------------"
  echo "Creating NodeDIDs..."
  echo "------------------------------------"
  export NODE_A_DID=$(setupNode "http://localhost:18081" "nodeA:5555")
  printf "NodeDID for node-a: %s\n" "$NODE_A_DID"
  waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 2 10
  export NODE_B_DID=$(setupNode "http://localhost:28081" "nodeB:5555")
  printf "NodeDID for node-b: %s\n" "$NODE_B_DID"
  waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 4 10

  echo "------------------------------------"
  echo "Restarting with NodeDID set and storage.kv.backend=sql..."
  echo "------------------------------------"
  # Start without bootstrap node but with discovery, to enforce authenticated, discovered connections (required for private transactions)
  export BOOTSTRAP_NODES=
  export ENABLE_DISCOVERY=true
  export KV_BACKEND=sql
  docker compose stop nodeA nodeB
  docker compose up --wait nodeA nodeB || exitWithDockerLogs 1
  # The DAG must survive the switch: the bbolt files were imported into SQL
  waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 4 10
  waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 4 10
  assertBBoltMigrated nodeA
  assertBBoltMigrated nodeB

  echo "------------------------------------"
  echo "Issuing private credentials..."
  echo "------------------------------------"
  vcNodeA=$(createAuthCredential "http://localhost:18081" "$NODE_A_DID" "$NODE_B_DID")
  printf "VC issued by node A: %s\n" "$vcNodeA"
  vcNodeB=$(createAuthCredential "http://localhost:28081" "$NODE_B_DID" "$NODE_A_DID")
  printf "VC issued by node B: %s\n" "$vcNodeB"

  waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 6 30
  waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 6 30
  waitForAuthCredentialCount "NodeA" "http://localhost:18081" 2 30
  waitForAuthCredentialCount "NodeB" "http://localhost:28081" 2 30

  echo "------------------------------------"
  echo "Revoking NutsAuthorizationCredential..."
  echo "------------------------------------"
  revokeCredential "http://localhost:18081" "${vcNodeA}"
  revokeCredential "http://localhost:28081" "${vcNodeB}"

  waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 8 30
  waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 8 30
  waitForAuthCredentialCount "NodeA" "http://localhost:18081" 0 30
  waitForAuthCredentialCount "NodeB" "http://localhost:28081" 0 30

  echo "------------------------------------"
  echo "Restarting nodes, asserting state survived..."
  echo "------------------------------------"
  docker compose stop nodeA nodeB
  docker compose up --wait nodeA nodeB || exitWithDockerLogs 1
  waitForTXCount "NodeA" "http://localhost:18081/status/diagnostics" 8 10
  waitForTXCount "NodeB" "http://localhost:28081/status/diagnostics" 8 10
  waitForAuthCredentialCount "NodeA" "http://localhost:18081" 0 10
  waitForAuthCredentialCount "NodeB" "http://localhost:28081" 0 10

  echo "------------------------------------"
  echo "Stopping Docker containers..."
  echo "------------------------------------"
  docker compose --profile '*' down -v --remove-orphans
}

# Allow running a subset locally, e.g. ./run-test.sh sqlite postgres
VARIANTS=${*:-sqlite postgres mysql sqlserver}
for variant in $VARIANTS; do
  runVariant "$variant"
done
