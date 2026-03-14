# Memory Profiling Test for SearchVCs

## Purpose

This test measures memory allocation and GC behavior during parallel SearchVCs operations to investigate the reported issue:
- **Reported Problem:** Parallel bursts of transactions with 4 SearchVCs() per transaction cause 650MB/sec allocation rate, leading to CPU spikes
- **Root Cause:** GC thrashing from massive short-lived allocations (see `ANALYSIS-eOverdracht-CPU-issue.md`)

## Test Scenarios

### Scenario 1: Normal Load Pattern
- Database: **500 NutsAuthorizationCredentials** (realistic production size)
- 10 iterations
- 4 parallel searches per iteration
- 2 seconds between iterations
- Total: 40 searches over 20 seconds
- Measures: Allocation per burst, GC frequency
- Each search will return more results (~250 credentials matching the query)

### Scenario 2: Intensive Burst Load
- Same 500-credential database
- 50 iterations
- 4 parallel searches per iteration
- No delay between iterations (as fast as possible)
- Total: 200 searches in ~10-20 seconds
- Simulates: High-traffic eOverdracht scenario with realistic data volume
- Expected: Reproduces the 650MB/s issue with production-scale data

## What It Measures

### Memory Metrics (from Prometheus `/metrics` endpoint)
- `go_memstats_alloc_bytes` - Current heap allocation
- `go_memstats_heap_alloc_bytes` - Heap allocation
- `go_memstats_sys_bytes` - Total memory obtained from OS
- `go_memstats_mallocs_total` - Total allocations
- `go_memstats_frees_total` - Total frees
- `go_gc_cycles_total` - Number of GC cycles
- `go_gc_duration_seconds` - GC pause times

### Calculated Metrics
- **Allocation rate**: MB/second allocated
- **GC frequency**: Seconds between GC cycles
- **Memory churn**: Allocations per search operation

## Running the Test

### Basic Run
```bash
cd e2e-tests/nuts-network/memory-profiling-search
./run-test.sh
```

### With Memory Limit Testing (512MB container simulation)
Edit `docker-compose.yml` and uncomment:
```yaml
GOGC: "200"
GOMEMLIMIT: "340MiB"
```

Then run:
```bash
./run-test.sh
```

### With Go Profiling
1. Ensure pprof ports are exposed (already configured: 16060, 26060)
2. Run test in background:
```bash
./run-test.sh &
TEST_PID=$!
```
3. During intensive load phase, capture heap profile:
```bash
# Wait for test to start intensive phase (check output)
curl http://localhost:16060/debug/pprof/heap > heap-before.prof
# Let intensive phase complete
sleep 20
curl http://localhost:16060/debug/pprof/heap > heap-after.prof
```
4. Analyze with pprof:
```bash
go tool pprof -http=:8080 heap-after.prof
# Or compare before/after:
go tool pprof -http=:8080 -base heap-before.prof heap-after.prof
```

## Expected Results

### Baseline (No Optimization) - With 500 Credentials
Based on analysis in `ANALYSIS-eOverdracht-CPU-issue.md`:
- **Allocation per search**: ~5-10MB (significantly more due to 250 results per query)
- **4 parallel searches**: 20-40MB allocated per burst
- **With 500 credentials in DB**: Each search returns ~250 credentials
- **Per-search breakdown**:
  - BBolt query: 500KB (250 documents × ~2KB)
  - JSON unmarshal: 2KB × 250 = 500KB
  - Verification: 5KB × 250 = 1.25MB
  - Total: **~5-10MB per search** (vs 1MB with 20 credentials)

### Intensive Load Expected Results - Production Scale
- **Search rate**: 15-20 searches/sec
- **Allocation rate**: **100-650 MB/sec** (matches reported issue!)
- **GC frequency**: Every 1-3 seconds (severe thrashing)
- **GC CPU overhead**: 20-40%

### With GOGC=200 GOMEMLIMIT=340MiB
- **GC frequency**: Every 10-20 seconds (50% improvement)
- **Allocation rate**: Same (no change)
- **CPU overhead**: 10-20% GC (improvement)
- **Memory**: Grows to 250-300MB

### With Caching (After Implementing Fix)
- **First search**: 1MB allocation
- **Next 3 parallel searches**: Cache hits, ~0 bytes
- **Allocation rate**: 75% reduction
- **GC frequency**: 75% reduction
- **CPU overhead**: 60-80% reduction

## Interpreting Results

### 🔴 Critical Issues (Matches Reported Problem)
```
Allocation rate: > 100 MB/sec
GC cycles: > 10 in 20 seconds
GC frequency: < 2 seconds between cycles
```
**Action**: Implement caching immediately (see `FIX-GC-thrashing-POC.md`)

### ⚠️ Warning Signs
```
Allocation rate: 50-100 MB/sec
GC cycles: 5-10 in 20 seconds
GC frequency: 2-4 seconds between cycles
```
**Action**: Apply GOGC/GOMEMLIMIT tuning, plan caching implementation

### ✅ Acceptable Performance
```
Allocation rate: < 50 MB/sec
GC cycles: < 5 in 20 seconds  
GC frequency: > 4 seconds between cycles
```
**Action**: Monitor, no immediate changes needed

## Analyzing GC Trace Output

The test enables `GODEBUG=gctrace=1`. Look for patterns like:

```
gc 10 @5.2s 2%: 0.015+10+0.025 ms clock, 200->200->125 MB, 250 MB goal, 4 P
```

Breakdown:
- `gc 10`: GC cycle number 10
- `@5.2s`: 5.2 seconds since start
- `2%`: 2% of CPU time spent in GC
- `0.015+10+0.025 ms`: GC phases (stop-the-world + concurrent + stop-the-world)
- `200->200->125 MB`: Heap before -> after GC -> live data
- `250 MB goal`: Next GC will trigger at 250MB
- `4 P`: 4 processors

**Bad pattern (GC thrashing):**
```
gc 10 @5.2s 15%: ...
gc 11 @5.8s 18%: ...  ← Only 0.6s between GCs
gc 12 @6.3s 20%: ...  ← Only 0.5s between GCs
```

## Troubleshooting

### Test Fails to Start
```bash
# Clean up any existing containers
docker compose down -v
rm -rf ./node-*/data

# Try again
./run-test.sh
```

### Can't Access Metrics Endpoint
```bash
# Check if containers are running
docker compose ps

# Check nodeA logs
docker compose logs nodeA | tail -50

# Verify metrics endpoint
curl -s http://localhost:11323/metrics | head -20
```

### Out of Memory During Test
This means you've successfully reproduced the issue! The test will show:
```
🔴 CRITICAL: High allocation rate detected: XXX MB/sec
```

Capture the output and compare with `ANALYSIS-eOverdracht-CPU-issue.md`.

## Next Steps After Running Test

1. **Document Results**: Save the output showing allocation rates and GC frequency
2. **Compare with Analysis**: See if results match `ANALYSIS-eOverdracht-CPU-issue.md` predictions
3. **Test Mitigations**:
   - Run with `GOGC=200 GOMEMLIMIT=340MiB` (expect 30-50% improvement)
   - Implement caching (see `FIX-GC-thrashing-POC.md`, expect 75% improvement)
4. **Profile with pprof**: Identify exact allocation hotspots
5. **Create Benchmark**: Convert to Go benchmark test for continuous monitoring

## Related Documentation

- `ANALYSIS-eOverdracht-CPU-issue.md` - Root cause analysis
- `FIX-GC-thrashing-POC.md` - Implementation guide for fixes
- `MEMORY-LAYOUT-512MB-with-BBolt.md` - Memory layout explanation
- `QUICK-FIX-512MB-container.md` - Quick deployment guide

## Test Data

The test creates:
- **500 NutsAuthorizationCredentials** (250 per node)
- Each credential is ~2KB
- Total database size: ~1MB credentials + indexes
- BBolt database size: ~2-5MB (plus internal overhead)
- Each search query will match ~250 credentials (realistic load)

**This matches production scale more closely:**
- Real production scenarios typically have 100-1000+ credentials
- Search queries return 50-500 results
- More realistic allocation patterns
- More accurate BBolt contention simulation

## Performance Baseline

For comparison, expected performance on modern hardware (4 CPU, 8GB RAM):
- **Without optimization**: 15-20 searches/sec, 20-40 MB/sec allocation
- **With GOGC tuning**: 15-20 searches/sec, same allocation, less GC
- **With caching**: 50-100 searches/sec, 5-10 MB/sec allocation

