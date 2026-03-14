#!/usr/bin/env bash

set -e

source ../../util.sh

echo "=========================================="
echo "Memory Profiling Test for SearchVCs"
echo "=========================================="
echo "This test simulates the reported issue:"
echo "- Parallel bursts of TXs"
echo "- 4 SearchVCs() per transaction"
echo "- Expected: 650MB/s allocation causing CPU spike"
echo "=========================================="

function searchAuthCredentials() {
  local NODE_URL=$1
  local SUBJECT_ID=${2:-$NODE_A_DID}
  printf '{
    "query": {
      "@context": ["https://www.w3.org/2018/credentials/v1", "https://nuts.nl/credentials/v1"],
      "type": ["VerifiableCredential" ,"NutsAuthorizationCredential"],
      "credentialSubject": {
        "id": "%s",
        "purposeOfUse": "example"
      }
    },
    "searchOptions": {
       "allowUntrustedIssuer": true
    }
  }' "$SUBJECT_ID" | curl -s -X POST "$NODE_URL/internal/vcr/v2/search" -H "Content-Type: application/json" --data-binary @-
}

# Perform 4 parallel searches (simulating the reported pattern)
function parallel4Searches() {
  local NODE_URL=$1
  searchAuthCredentials "$NODE_URL" > /dev/null &
  searchAuthCredentials "$NODE_URL" > /dev/null &
  searchAuthCredentials "$NODE_URL" > /dev/null &
  searchAuthCredentials "$NODE_URL" > /dev/null &
  wait
}

# Get memory stats from Prometheus metrics
function getMemoryStats() {
  local NODE_URL=$1
  echo "Memory stats from $NODE_URL/metrics:"
  curl -s "$NODE_URL/metrics" | grep -E "go_memstats_(alloc_bytes|heap_alloc_bytes|sys_bytes|mallocs_total|frees_total)" | grep -v "#"
}

# Get GC stats
function getGCStats() {
  local NODE_URL=$1
  echo "GC stats from $NODE_URL/metrics:"
  curl -s "$NODE_URL/metrics" | grep -E "go_gc_(duration_seconds|cycles_total)" | grep -v "#"
}

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
export NODE_A_DID=
export NODE_B_DID=
export BOOTSTRAP_NODES=nodeA:5555
docker compose down
docker compose rm -f -v
rm -rf ./node-*/data

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
mkdir -p ./node-A/data/network ./node-B/data/network
docker compose up --wait

echo "------------------------------------"
echo "Creating NodeDIDs..."
echo "------------------------------------"
export NODE_A_DID=$(setupNode "http://localhost:11323" "nodeA:5555")
printf "NodeDID for node-a: %s\n" "$NODE_A_DID"
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 2 10
export NODE_B_DID=$(setupNode "http://localhost:21323" "nodeB:5555")
printf "NodeDID for node-b: %s\n" "$NODE_B_DID"
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 4 10

echo "------------------------------------"
echo "Restarting with NodeDID set..."
echo "------------------------------------"
export BOOTSTRAP_NODES=
docker compose stop
rm -rf ./node-*/data/network/connections.db
docker compose up --wait

echo "------------------------------------"
echo "Creating test credentials..."
echo "------------------------------------"
echo "Creating 2000 NutsAuthorizationCredentials to populate the database..."
echo "This will take several minutes..."

# Create 1000 credentials on each node (2000 total)
for i in {1..1000}; do
  vcA=$(createAuthCredential "http://localhost:11323" "$NODE_A_DID" "$NODE_B_DID")
  vcB=$(createAuthCredential "http://localhost:21323" "$NODE_B_DID" "$NODE_A_DID")

  # Show progress every 100 credentials
  if [ $((i % 100)) -eq 0 ]; then
    printf "  [%4d/2000] VCs created...\n" $((i*2))
  fi
done

echo "  [2000/2000] All VCs created!"

# Wait for all transactions to sync
echo "Waiting for all credentials to sync (this may take a minute)..."
# 4 DID transactions + 2000 VC transactions = 2004 total
waitForTXCount "NodeA" "http://localhost:11323/status/diagnostics" 2004 180
waitForTXCount "NodeB" "http://localhost:21323/status/diagnostics" 2004 180

echo "------------------------------------"
echo "Baseline memory measurement..."
echo "------------------------------------"
echo ""
echo "=== Node A Baseline ==="
getMemoryStats "http://localhost:11323"
getGCStats "http://localhost:11323"
echo ""
echo "=== Node B Baseline ==="
getMemoryStats "http://localhost:21323"
getGCStats "http://localhost:21323"
echo ""

# Record baseline (convert scientific notation to integers)
baseline_alloc_a=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_alloc_bytes " | awk '{printf "%.0f", $2}')
baseline_mallocs_a=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_mallocs_total " | awk '{printf "%.0f", $2}')
baseline_gc_a=$(curl -s "http://localhost:11323/metrics" | grep "go_gc_cycles_total " | awk '{printf "%.0f", $2}')

echo "------------------------------------"
echo "Starting memory profiling test..."
echo "------------------------------------"
echo "Simulating parallel burst pattern:"
echo "- 50 iterations (increased from 10)"
echo "- 4 parallel searches per iteration"
echo "- 1 second between iterations"
echo "- Total: 200 searches over 50 seconds"
echo "- Metrics captured DURING search execution"
echo ""

START_TIME=$(date +%s)

for iteration in {1..50}; do
  echo "[Iteration $iteration/50] Running 4 parallel searches..."

  # Capture pre-iteration stats (convert scientific notation to integer)
  pre_alloc=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_alloc_bytes " | awk '{printf "%.0f", $2}')
  pre_heap=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_heap_alloc_bytes " | awk '{printf "%.0f", $2}')
  pre_mallocs=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_mallocs_total " | awk '{printf "%.0f", $2}')

  # Start 4 parallel searches in background
  searchAuthCredentials "http://localhost:11323" > /dev/null &
  PID1=$!
  searchAuthCredentials "http://localhost:11323" > /dev/null &
  PID2=$!
  searchAuthCredentials "http://localhost:11323" > /dev/null &
  PID3=$!
  searchAuthCredentials "http://localhost:11323" > /dev/null &
  PID4=$!

  # Capture stats DURING search execution (after 100ms)
  sleep 0.1
  during_alloc=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_alloc_bytes " | awk '{printf "%.0f", $2}')
  during_heap=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_heap_alloc_bytes " | awk '{printf "%.0f", $2}')
  during_mallocs=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_mallocs_total " | awk '{printf "%.0f", $2}')

  # Wait for searches to complete
  wait $PID1 $PID2 $PID3 $PID4

  # Capture post-iteration stats (convert scientific notation to integer)
  post_alloc=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_alloc_bytes " | awk '{printf "%.0f", $2}')
  post_heap=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_heap_alloc_bytes " | awk '{printf "%.0f", $2}')
  post_mallocs=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_mallocs_total " | awk '{printf "%.0f", $2}')

  # Calculate allocation during search execution
  during_alloc_diff=$(echo "$during_alloc - $pre_alloc" | bc 2>/dev/null || echo "0")
  during_heap_diff=$(echo "$during_heap - $pre_heap" | bc 2>/dev/null || echo "0")
  during_mallocs_diff=$(echo "$during_mallocs - $pre_mallocs" | bc 2>/dev/null || echo "0")

  # Calculate total allocation for the full iteration
  total_alloc_diff=$(echo "$post_alloc - $pre_alloc" | bc 2>/dev/null || echo "0")
  total_heap_diff=$(echo "$post_heap - $pre_heap" | bc 2>/dev/null || echo "0")
  total_mallocs_diff=$(echo "$post_mallocs - $pre_mallocs" | bc 2>/dev/null || echo "0")

  # Format output - show both during and total
  if [ "$during_alloc_diff" != "0" ] && [ -n "$during_alloc_diff" ]; then
    during_mb=$(echo "scale=2; $during_alloc_diff / 1048576" | bc)
    printf "  DURING search (100ms): %s bytes (%.2f MB) - %s allocs\n" "$during_alloc_diff" "$during_mb" "$during_mallocs_diff"
  fi
  if [ "$total_alloc_diff" != "0" ] && [ -n "$total_alloc_diff" ]; then
    total_mb=$(echo "scale=2; $total_alloc_diff / 1048576" | bc)
    printf "  TOTAL iteration:       %s bytes (%.2f MB) - %s allocs\n" "$total_alloc_diff" "$total_mb" "$total_mallocs_diff"
  fi
  if [ "$total_heap_diff" != "0" ] && [ -n "$total_heap_diff" ]; then
    heap_mb=$(echo "scale=2; $total_heap_diff / 1048576" | bc)
    printf "  Heap change:           %s bytes (%.2f MB)\n" "$total_heap_diff" "$heap_mb"
  fi

  sleep 1
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "------------------------------------"
echo "Post-test memory measurement..."
echo "------------------------------------"
echo ""
echo "=== Node A Post-Test ==="
getMemoryStats "http://localhost:11323"
getGCStats "http://localhost:11323"
echo ""

# Calculate deltas (convert scientific notation to integers)
post_alloc_a=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_alloc_bytes " | awk '{printf "%.0f", $2}')
post_mallocs_a=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_mallocs_total " | awk '{printf "%.0f", $2}')
post_gc_a=$(curl -s "http://localhost:11323/metrics" | grep "go_gc_cycles_total " | awk '{printf "%.0f", $2}')

total_mallocs=$(echo "$post_mallocs_a - $baseline_mallocs_a" | bc 2>/dev/null || echo "0")
gc_cycles=$(echo "$post_gc_a - $baseline_gc_a" | bc 2>/dev/null || echo "0")

echo "=========================================="
echo "MEMORY PROFILING RESULTS"
echo "=========================================="
echo "Test duration: ${DURATION}s"
echo "Total searches: 200 (50 iterations × 4 parallel)"
echo ""
echo "Memory Impact:"
echo "  Total allocations: $total_mallocs"
if [ "$DURATION" -gt 0 ]; then
  echo "  Allocation rate: $(echo "scale=2; $total_mallocs / $DURATION" | bc) allocs/sec"
fi
echo "  GC cycles triggered: $gc_cycles"
if [ "$gc_cycles" -gt 0 ]; then
  echo "  GC frequency: $(echo "scale=2; $DURATION / $gc_cycles" | bc) seconds between GCs"
fi
echo ""

# Check if we can reproduce the reported issue (650MB/s)
if [ "$gc_cycles" -gt 10 ]; then
  echo "⚠️  HIGH GC ACTIVITY DETECTED!"
  echo "   GC ran $gc_cycles times in ${DURATION}s"
  echo "   This indicates memory pressure from allocation churn"
fi

if [ "$total_mallocs" -gt 1000000 ]; then
  echo "⚠️  HIGH ALLOCATION RATE DETECTED!"
  echo "   More than 1M allocations in ${DURATION}s"
  echo "   This matches the reported issue pattern"
fi

echo ""
echo "------------------------------------"
echo "Intensive load test (rapid parallel searches)..."
echo "------------------------------------"
echo "Running 100 iterations of 4 parallel searches..."
echo "This simulates a burst of transactions..."
echo "Capturing metrics DURING search execution every 10 iterations..."
echo ""

intensive_start=$(date +%s)
pre_alloc=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_alloc_bytes_total " | awk '{printf "%.0f", $2}')
pre_heap=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_heap_alloc_bytes " | awk '{printf "%.0f", $2}')
pre_gc=$(curl -s "http://localhost:11323/metrics" | grep "go_gc_cycles_total " | awk '{printf "%.0f", $2}')
pre_mallocs=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_mallocs_total " | awk '{printf "%.0f", $2}')

for i in {1..100}; do
  # Launch 4 parallel searches
  searchAuthCredentials "http://localhost:11323" > /dev/null &
  searchAuthCredentials "http://localhost:11323" > /dev/null &
  searchAuthCredentials "http://localhost:11323" > /dev/null &
  searchAuthCredentials "http://localhost:11323" > /dev/null &

  # Capture metrics WHILE searches are running (don't wait)
  if [ $((i % 10)) -eq 0 ]; then
    # Sample memory while searches are in progress
    sample_heap=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_heap_alloc_bytes " | awk '{printf "%.0f", $2}')
    sample_alloc=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_alloc_bytes_total " | awk '{printf "%.0f", $2}')
    sample_gc=$(curl -s "http://localhost:11323/metrics" | grep "go_gc_cycles_total " | awk '{printf "%.0f", $2}')

    # Calculate current rates
    current_time=$(date +%s)
    elapsed=$((current_time - intensive_start))
    if [ "$elapsed" -gt 0 ]; then
      alloc_so_far=$(echo "$sample_alloc - $pre_alloc" | bc 2>/dev/null || echo "0")
      gc_so_far=$(echo "$sample_gc - $pre_gc" | bc 2>/dev/null || echo "0")
      alloc_rate_mb=$(echo "scale=1; $alloc_so_far / $elapsed / 1048576" | bc)
      heap_mb=$(echo "scale=1; $sample_heap / 1048576" | bc)

      printf "  [%3d/100] Heap: %s MB, Allocated: %s MB/sec, GC: %s cycles\n" "$i" "$heap_mb" "$alloc_rate_mb" "$gc_so_far"
    fi
  fi

  # Wait for all 4 to complete before next iteration
  wait

  # Small delay between bursts
  sleep 0.1
done

intensive_end=$(date +%s)
post_alloc=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_alloc_bytes_total " | awk '{printf "%.0f", $2}')
post_heap=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_heap_alloc_bytes " | awk '{printf "%.0f", $2}')
post_gc=$(curl -s "http://localhost:11323/metrics" | grep "go_gc_cycles_total " | awk '{printf "%.0f", $2}')
post_mallocs=$(curl -s "http://localhost:11323/metrics" | grep "go_memstats_mallocs_total " | awk '{printf "%.0f", $2}')

intensive_duration=$((intensive_end - intensive_start))
intensive_alloc=$(echo "$post_alloc - $pre_alloc" | bc 2>/dev/null || echo "0")
intensive_gc=$(echo "$post_gc - $pre_gc" | bc 2>/dev/null || echo "0")
intensive_mallocs=$(echo "$post_mallocs - $pre_mallocs" | bc 2>/dev/null || echo "0")

echo ""
echo "=========================================="
echo "INTENSIVE LOAD TEST RESULTS"
echo "=========================================="
echo "Duration: ${intensive_duration}s"
echo "Total searches: 400 (100 iterations × 4 parallel)"
if [ "$intensive_duration" -gt 0 ]; then
  echo "Search rate: $(echo "scale=2; 400 / $intensive_duration" | bc) searches/sec"
fi
echo ""
echo "Memory Impact:"
echo "  Total allocated: $(echo "scale=2; $intensive_alloc / 1048576" | bc) MB"
if [ "$intensive_duration" -gt 0 ]; then
  echo "  Allocation rate: $(echo "scale=0; $intensive_alloc / $intensive_duration / 1048576" | bc) MB/sec"
fi
echo "  Total allocations: $intensive_mallocs"
echo "  GC cycles: $intensive_gc"
if [ "$intensive_gc" -gt 0 ]; then
  echo "  GC frequency: $(echo "scale=2; $intensive_duration / $intensive_gc" | bc)s between cycles"
fi
echo ""

# Check for the reported 650MB/s issue
if [ "$intensive_duration" -gt 0 ]; then
  alloc_rate_mb=$(echo "scale=0; $intensive_alloc / $intensive_duration / 1048576" | bc)
  if [ "$alloc_rate_mb" -gt 100 ]; then
    echo "🔴 CRITICAL: High allocation rate detected: ${alloc_rate_mb} MB/sec"
    echo "   This matches or exceeds the reported 650MB/s issue!"
    echo "   Recommendation: Implement search result caching immediately"
  fi
fi

if [ "$intensive_gc" -gt 20 ]; then
  echo "🔴 CRITICAL: GC thrashing detected!"
  echo "   GC ran $intensive_gc times in ${intensive_duration}s"
  if [ "$intensive_duration" -gt 0 ]; then
    echo "   GC frequency: $(echo "scale=2; $intensive_duration / $intensive_gc" | bc)s between cycles"
  fi
  echo "   This indicates severe memory pressure"
fi

echo ""
echo "------------------------------------"
echo "Final memory state..."
echo "------------------------------------"
getMemoryStats "http://localhost:11323"
getGCStats "http://localhost:11323"

echo ""
echo "=========================================="
echo "TEST COMPLETE"
echo "=========================================="
echo "To analyze in detail, enable Go profiling:"
echo "  1. Add to docker-compose.yml: GODEBUG=gctrace=1"
echo "  2. Expose pprof: add port 6060:6060"
echo "  3. Run: go tool pprof http://localhost:6060/debug/pprof/heap"
echo ""
echo "See ANALYSIS-eOverdracht-CPU-issue.md for mitigation strategies"
echo ""

echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop

