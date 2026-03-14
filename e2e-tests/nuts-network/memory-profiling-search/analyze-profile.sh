#!/usr/bin/env bash

# Helper script for analyzing memory profiles from the memory-profiling-search test

set -e

echo "=========================================="
echo "Memory Profile Analysis Helper"
echo "=========================================="
echo ""

function show_usage() {
  echo "Usage: $0 <command>"
  echo ""
  echo "Commands:"
  echo "  capture-heap       - Capture heap profile from running node"
  echo "  capture-alloc      - Capture allocation profile"
  echo "  capture-goroutine  - Capture goroutine profile"
  echo "  analyze-heap       - Analyze heap profile interactively"
  echo "  top-allocations    - Show top memory allocations"
  echo "  compare <before> <after> - Compare two heap profiles"
  echo "  live-stats         - Show live memory statistics"
  echo ""
  echo "Examples:"
  echo "  $0 capture-heap           # Saves to heap-TIMESTAMP.prof"
  echo "  $0 analyze-heap heap-123.prof"
  echo "  $0 compare heap-before.prof heap-after.prof"
  echo "  $0 live-stats             # Watch memory in real-time"
}

NODE_URL="http://localhost:11323"
PPROF_URL="http://localhost:16060"

if [ $# -eq 0 ]; then
  show_usage
  exit 0
fi

COMMAND=$1

case "$COMMAND" in
  "capture-heap")
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    FILENAME="heap-${TIMESTAMP}.prof"
    echo "Capturing heap profile from ${PPROF_URL}/debug/pprof/heap..."
    curl -s "${PPROF_URL}/debug/pprof/heap" > "${FILENAME}"
    echo "✅ Saved to: ${FILENAME}"
    echo ""
    echo "To analyze:"
    echo "  go tool pprof ${FILENAME}"
    echo "  go tool pprof -http=:8080 ${FILENAME}"
    ;;

  "capture-alloc")
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    FILENAME="allocs-${TIMESTAMP}.prof"
    echo "Capturing allocation profile from ${PPROF_URL}/debug/pprof/allocs..."
    curl -s "${PPROF_URL}/debug/pprof/allocs" > "${FILENAME}"
    echo "✅ Saved to: ${FILENAME}"
    echo ""
    echo "To analyze:"
    echo "  go tool pprof -alloc_space ${FILENAME}"
    ;;

  "capture-goroutine")
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    FILENAME="goroutine-${TIMESTAMP}.prof"
    echo "Capturing goroutine profile from ${PPROF_URL}/debug/pprof/goroutine..."
    curl -s "${PPROF_URL}/debug/pprof/goroutine" > "${FILENAME}"
    echo "✅ Saved to: ${FILENAME}"
    echo ""
    echo "To analyze:"
    echo "  go tool pprof ${FILENAME}"
    ;;

  "analyze-heap")
    if [ $# -lt 2 ]; then
      echo "Error: Please provide heap profile file"
      echo "Usage: $0 analyze-heap <heap-profile.prof>"
      exit 1
    fi
    PROFILE=$2
    echo "Analyzing heap profile: ${PROFILE}"
    echo "Opening interactive pprof web UI on http://localhost:8080"
    echo ""
    go tool pprof -http=:8080 "${PROFILE}"
    ;;

  "top-allocations")
    if [ $# -lt 2 ]; then
      echo "Capturing current heap profile for analysis..."
      PROFILE="heap-temp.prof"
      curl -s "${PPROF_URL}/debug/pprof/heap" > "${PROFILE}"
    else
      PROFILE=$2
    fi

    echo "=========================================="
    echo "Top 20 Memory Allocations"
    echo "=========================================="
    echo ""
    go tool pprof -top -cum "${PROFILE}" | head -30

    echo ""
    echo "=========================================="
    echo "SearchVCs Related Allocations"
    echo "=========================================="
    echo ""
    go tool pprof -list="Search|search" "${PROFILE}" | head -50 || echo "No SearchVCs allocations found"
    ;;

  "compare")
    if [ $# -lt 3 ]; then
      echo "Error: Please provide two profile files to compare"
      echo "Usage: $0 compare <before.prof> <after.prof>"
      exit 1
    fi
    BEFORE=$2
    AFTER=$3
    echo "Comparing profiles:"
    echo "  Before: ${BEFORE}"
    echo "  After:  ${AFTER}"
    echo ""
    echo "Opening comparison in web UI on http://localhost:8080"
    echo ""
    go tool pprof -http=:8080 -base "${BEFORE}" "${AFTER}"
    ;;

  "live-stats")
    echo "Monitoring live memory statistics from ${NODE_URL}/metrics"
    echo "Press Ctrl+C to stop"
    echo ""
    echo "Timestamp | Heap Alloc | Sys Memory | GC Cycles | Alloc Rate"
    echo "----------|------------|------------|-----------|------------"

    prev_alloc=0
    prev_time=$(date +%s)

    while true; do
      heap_alloc=$(curl -s "${NODE_URL}/metrics" | grep "^go_memstats_heap_alloc_bytes " | awk '{print $2}')
      sys_mem=$(curl -s "${NODE_URL}/metrics" | grep "^go_memstats_sys_bytes " | awk '{print $2}')
      gc_cycles=$(curl -s "${NODE_URL}/metrics" | grep "^go_gc_cycles_total " | awk '{print $2}')
      mallocs=$(curl -s "${NODE_URL}/metrics" | grep "^go_memstats_mallocs_total " | awk '{print $2}')

      heap_mb=$(echo "scale=2; $heap_alloc / 1024 / 1024" | bc)
      sys_mb=$(echo "scale=2; $sys_mem / 1024 / 1024" | bc)

      # Calculate allocation rate
      current_time=$(date +%s)
      time_diff=$((current_time - prev_time))
      if [ $time_diff -gt 0 ] && [ $prev_alloc -ne 0 ]; then
        alloc_diff=$(echo "$mallocs - $prev_alloc" | bc)
        alloc_rate=$(echo "scale=0; $alloc_diff / $time_diff" | bc)
      else
        alloc_rate=0
      fi
      prev_alloc=$mallocs
      prev_time=$current_time

      timestamp=$(date +%H:%M:%S)
      printf "%s | %8.2f MB | %8.2f MB | %9s | %10s/s\n" "$timestamp" "$heap_mb" "$sys_mb" "$gc_cycles" "$alloc_rate"

      sleep 2
    done
    ;;

  "help"|"--help"|"-h")
    show_usage
    ;;

  *)
    echo "Error: Unknown command: $COMMAND"
    echo ""
    show_usage
    exit 1
    ;;
esac

