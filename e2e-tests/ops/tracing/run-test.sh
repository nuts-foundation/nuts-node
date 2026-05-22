#!/usr/bin/env bash
# shellcheck disable=SC1091
source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d --remove-orphans
docker compose up --wait nodeA jaeger

echo "------------------------------------"
echo "Sending traced request to node..."
echo "------------------------------------"
# /status, /health and /metrics are excluded from tracing, so use an API endpoint that is traced.
TRACE_ID=$(openssl rand -hex 16)
TRACEPARENT="00-${TRACE_ID}-$(openssl rand -hex 8)-01"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:18081/internal/vdr/v2/subject -H "traceparent: $TRACEPARENT")
if [ "$RESPONSE" -eq 200 ]; then
  echo "Request successful"
else
  echo "FAILED: Expected HTTP 200 from /internal/vdr/v2/subject, got $RESPONSE" 1>&2
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Verifying trace in Jaeger..."
echo "------------------------------------"
if ! assertJaegerTrace "http://localhost:16686" "$TRACE_ID" "nodeA" ""; then
  exitWithDockerLogs 1
fi

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose down
