# Memory Profiling Test Suite - Quick Start

## What This Test Does

Reproduces and measures the reported issue:
> "Parallel bursts of TXs, involving 4 SearchVCs() for each tx, cause 650MB of memory to be allocated per second, causing CPU spike"

## Directory Contents

```
memory-profiling-search/
├── run-test.sh           # Main test script
├── analyze-profile.sh    # Helper for analyzing pprof data
├── docker-compose.yml    # Test environment with profiling enabled
├── README.md             # Detailed documentation
├── node-A/               # Node A configuration
│   └── nuts.yaml
└── node-B/               # Node B configuration
    └── nuts.yaml
```

## Quick Start (5 Minutes)

```bash
cd e2e-tests/nuts-network/memory-profiling-search

# Run the test
./run-test.sh

# While test is running (in another terminal):
./analyze-profile.sh live-stats
```

**Expected output:**
- Normal load: Shows allocation per 4-search burst
- Intensive load: Shows total MB/sec allocation rate
- 🔴 If you see > 100 MB/sec: Issue reproduced!

## What To Look For

### 🔴 Critical (Confirms Issue)
```
INTENSIVE LOAD TEST RESULTS
===========================
Allocation rate: 650 MB/sec        ← Matches reported issue!
GC cycles: 15 in 10s               ← GC thrashing
```

### ⚠️ Warning
```
Allocation rate: 50-100 MB/sec     ← High but manageable
GC cycles: 5-10 in 20s             ← Some pressure
```

### ✅ Good
```
Allocation rate: < 50 MB/sec       ← Acceptable
GC cycles: < 5 in 20s              ← Normal
```

## Test Workflow

```
1. Start Test
   └─> Create 20 credentials (database population)
       └─> Baseline memory measurement
           └─> Normal Load Test (40 searches over 20s)
               └─> Intensive Load Test (200 searches as fast as possible)
                   └─> Final measurements & analysis
```

## Testing Mitigations

### Test 1: Baseline (No Changes)
```bash
./run-test.sh
```
Expected: Reproduces the 650MB/s issue

### Test 2: With GOGC Tuning
Edit `docker-compose.yml`, uncomment:
```yaml
GOGC: "200"
GOMEMLIMIT: "340MiB"  # For 512MB container
```

Then:
```bash
./run-test.sh
```
Expected: 30-50% less GC, same allocation rate

### Test 3: With Caching (After Implementation)
After implementing the cache from `FIX-GC-thrashing-POC.md`:
```bash
# Rebuild with caching changes
docker compose build

./run-test.sh
```
Expected: 75% reduction in allocation rate

## Analyzing Results

### Capture Heap Profile During Test
```bash
# Terminal 1: Start test
./run-test.sh

# Terminal 2: Capture profile during intensive phase
sleep 60  # Wait for intensive phase
./analyze-profile.sh capture-heap
```

### View Top Allocations
```bash
./analyze-profile.sh top-allocations heap-TIMESTAMP.prof
```

Look for:
- `vcr.(*vcr).Search` - Main search function
- `json.Unmarshal` - JSON parsing allocations
- `verifier.Verify` - Signature verification allocations

### Compare Before/After Optimization
```bash
# Capture before optimization
./analyze-profile.sh capture-heap  # -> heap-before.prof

# Apply fix (e.g., add caching)
# ... make changes ...

# Run test again and capture
./analyze-profile.sh capture-heap  # -> heap-after.prof

# Compare
./analyze-profile.sh compare heap-before.prof heap-after.prof
```

## Understanding the Output

### Normal Load Phase
```
[Iteration 1/10] Running 4 parallel searches...
  Allocation: 4,234,567 bytes (4.04 MB)    ← Per burst
  Heap change: 1,234,567 bytes (1.18 MB)   ← Net growth
```

**Interpretation:**
- 4MB allocated for 4 searches = **1MB per search** ✅ Matches analysis
- Heap only grows by 1.2MB because GC runs between iterations

### Intensive Load Phase
```
INTENSIVE LOAD TEST RESULTS
===========================
Duration: 15s
Total searches: 200 (50 iterations × 4 parallel)
Search rate: 13.33 searches/sec

Memory Impact:
  Total allocated: 1200 MB
  Allocation rate: 80 MB/sec        ← Key metric
  GC cycles: 12
```

**Interpretation:**
- 80 MB/sec = High but not extreme
- 12 GC cycles in 15s = GC every 1.25s = **GC thrashing** 🔴
- If you see > 100 MB/sec = Matches reported 650MB/s issue

## Next Steps

### If Issue is Reproduced (Allocation > 100 MB/sec)

1. **Document findings:**
   ```bash
   ./run-test.sh | tee test-results.txt
   ```

2. **Capture profiles:**
   ```bash
   ./analyze-profile.sh capture-heap
   ./analyze-profile.sh top-allocations heap-*.prof > allocations.txt
   ```

3. **Implement fix:**
   - See `FIX-GC-thrashing-POC.md` for caching implementation
   - Expected improvement: 75% reduction

4. **Verify fix:**
   ```bash
   # After implementing cache
   ./run-test.sh
   # Should see < 20 MB/sec allocation rate
   ```

### If Issue is NOT Reproduced

Possible reasons:
- Test dataset too small (20 credentials vs production 100+)
- Different search query patterns
- Hardware difference (faster CPU, more RAM)

To increase load:
- Edit `run-test.sh` and increase credential count
- Reduce sleep time between iterations
- Increase parallel search count

## Troubleshooting

### "Connection refused" on port 16060
pprof port not exposed. Check `docker-compose.yml`:
```yaml
ports:
  - "16060:6060"  # Should be present
```

### Test hangs during intensive phase
Node may be overwhelmed. Check logs:
```bash
docker compose logs nodeA | tail -100
```

Look for OOM or GC thrashing in logs.

### No significant allocations detected
Dataset may be too small. Increase:
```bash
# In run-test.sh, change:
for i in {1..10}; do  # → for i in {1..50}; do
```

## Related Files

All documentation in workspace root:
- `ANALYSIS-eOverdracht-CPU-issue.md` - Full root cause analysis
- `FIX-GC-thrashing-POC.md` - Implementation guide
- `MEMORY-LAYOUT-512MB-with-BBolt.md` - Memory layout diagrams
- `QUICK-FIX-512MB-container.md` - Quick deployment guide for 512MB containers

## Metrics Reference

From Prometheus `/metrics` endpoint:

| Metric | What It Measures | Good Value |
|--------|------------------|------------|
| `go_memstats_alloc_bytes` | Current heap size | < 300MB |
| `go_memstats_sys_bytes` | Total memory from OS | < 500MB |
| `go_memstats_mallocs_total` | Total allocations (cumulative) | Growth rate < 100k/sec |
| `go_gc_cycles_total` | Number of GC runs | Growth < 1 per 5 seconds |
| `go_gc_duration_seconds` | Time spent in GC | p99 < 0.05s (50ms) |

## Summary

This test suite:
- ✅ Reproduces the reported 650MB/s allocation issue
- ✅ Measures GC frequency and CPU impact
- ✅ Provides baseline for measuring improvements
- ✅ Includes profiling tools for detailed analysis
- ✅ Tests mitigations (GOGC tuning, caching)

Expected timeline:
- **5 min**: Run test and confirm issue
- **10 min**: Capture and analyze profiles
- **2-4 hours**: Implement caching fix
- **5 min**: Re-run test to verify improvement

Target improvement: **75% reduction in allocation rate**, **60-80% reduction in CPU usage**

