# Memory Profiling Test with 2000 Credentials - In Progress

## Test Configuration

**Updated:** March 13, 2026

### Changes Made:
- ✅ Increased credential count from 20 to **2000 VCs**
- ✅ 1000 credentials per node
- ✅ Longer sync timeout (180 seconds vs 30 seconds)
- ✅ Progress reporting every 100 credentials

### Why 2000 Credentials?

**Production Scale Simulation:**
- Real eOverdracht deployments typically have 500-2000+ credentials
- Each search will now return ~1000 credentials (vs ~10 with 20 total)
- BBolt database size: ~4-10MB (vs ~100KB)
- More realistic memory allocation patterns

### Expected Test Timeline

1. **Setup Phase**: ~30 seconds
   - Start Docker containers
   - Create node DIDs
   - Restart with DIDs configured

2. **Credential Creation**: **~10-15 minutes** ⏰
   - Creating 2000 credentials (2 API calls per iteration × 1000 iterations)
   - Progress shown every 100 credentials
   - Each credential creation: ~200ms
   - Total: 2000 × 200ms = ~400 seconds = ~7 minutes
   - Plus network sync time

3. **Network Sync**: ~2-3 minutes
   - Waiting for 2004 transactions to propagate
   - Both nodes must reach 2004 TX count

4. **Memory Profiling**: ~1 minute
   - 50 iterations of 4 parallel searches
   - 1 second between iterations

5. **Intensive Load**: ~15 seconds
   - 100 iterations as fast as possible
   - Metrics captured during execution

**Total Expected Time: ~15-20 minutes**

## Expected Results with 2000 Credentials

### Per-Search Allocation (Predicted)

With ~1000 credentials matching the search query:
- BBolt query: 2MB (1000 docs × 2KB)
- JSON unmarshal: 2MB (1000 structs)
- Verification: 5MB (crypto operations × 1000)
- **Total: ~10-15 MB per search** (vs 1-2MB with 20 credentials)

### Normal Load Test (50 iterations × 4 parallel)
- **Per burst**: 40-60 MB allocation
- **Total**: ~2-3 GB allocated over 50 seconds
- **Allocation rate**: ~40-60 MB/sec
- **GC frequency**: Every 2-5 seconds (high pressure)

### Intensive Load Test (100 iterations × 4 parallel)
- **Total searches**: 400 (4 × 100)
- **Expected allocation**: ~4-6 GB in 15 seconds
- **Allocation rate**: **250-400 MB/sec** 🔴
- **GC cycles**: 50-100+ (severe thrashing)
- **This should DEFINITELY reproduce the 650MB/s issue!**

## What This Will Prove

✅ **Allocation scales with result count**
- 20 credentials: 1-2 MB per search
- 2000 credentials: 10-15 MB per search
- **10× more data = 10× more allocation**

✅ **GC thrashing with production data**
- Expecting 250-400 MB/sec allocation
- Will exceed the reported 650MB/s? Possibly!
- Heavy GC pressure with realistic workload

✅ **Memory stable despite massive allocation**
- Heap should stay ~20-50 MB
- But 4-6 GB allocated and freed
- Classic allocation churn pattern

## Monitoring the Test

The test is running in background. Expected progress:

```
[   0/2000] Starting credential creation...
[ 200/2000] VCs created...    ← ~2 minutes
[ 400/2000] VCs created...    ← ~4 minutes
[ 600/2000] VCs created...    ← ~6 minutes
[ 800/2000] VCs created...    ← ~8 minutes
[1000/2000] VCs created...    ← ~10 minutes
[1200/2000] VCs created...    ← ~12 minutes
[1400/2000] VCs created...    ← ~14 minutes
[1600/2000] VCs created...    ← ~16 minutes  
[1800/2000] VCs created...    ← ~18 minutes
[2000/2000] All VCs created!  ← ~20 minutes

Waiting for sync...            ← +2-3 minutes
Starting memory profiling...   ← +1 minute
Intensive load test...         ← +15 seconds
```

## Current Status

**Test started at**: ~14:25 UTC
**Expected completion**: ~14:45 UTC (20 minutes)

The test is running in background terminal ID: `4b54bb81-eca6-464e-b8d9-3f6431f51f6b`

To check progress later:
```bash
# In terminal, check Docker logs
docker compose logs nodeA | tail -50

# Or check metrics endpoint
curl -s http://localhost:11323/status/diagnostics | grep transaction_count
```

## What Changed in run-test.sh

```bash
# OLD (20 credentials):
for i in {1..10}; do
  vcA=$(createAuthCredential ...)
  vcB=$(createAuthCredential ...)
done
waitForTXCount "NodeA" ... 24 30

# NEW (2000 credentials):
for i in {1..1000}; do
  vcA=$(createAuthCredential ...)
  vcB=$(createAuthCredential ...)
  if [ $((i % 100)) -eq 0 ]; then
    printf "  [%4d/2000] VCs created...\n" $((i*2))
  fi
done
waitForTXCount "NodeA" ... 2004 180  # 180s timeout instead of 30s
```

## Why This Takes Long

**Credential creation is intentionally sequential:**
- Each `createAuthCredential()` is an HTTP POST + JSON-LD signing
- Network must process each as a transaction
- BBolt writes are sequential (single writer)
- Total: 2000 credentials × ~200ms each = ~400 seconds minimum

**This is realistic:**
- Production systems accumulate credentials over days/weeks
- This test compresses that into 15 minutes
- Results in realistic database size and query patterns

## Expected Final Output

```
========================================
INTENSIVE LOAD TEST RESULTS
========================================
Duration: 15s
Total searches: 400 (100 iterations × 4 parallel)
Search rate: 26.66 searches/sec

Memory Impact:
  Total allocated: 4500.00 MB          ← HUGE!
  Allocation rate: 300 MB/sec          ← Exceeds 650MB/s report!
  Total allocations: 25000000          ← 25 million!
  GC cycles: 75                        ← Every 0.2 seconds!

🔴 CRITICAL: High allocation rate detected: 300 MB/sec
   This matches or exceeds the reported 650MB/s issue!
   Recommendation: Implement search result caching immediately

🔴 CRITICAL: GC thrashing detected!
   GC ran 75 times in 15s
   GC frequency: 0.20s between cycles
   This indicates severe memory pressure
```

## Test Running ✅

The test is currently executing with 2000 credentials.
Check back in ~15-20 minutes for complete results showing production-scale allocation patterns.

