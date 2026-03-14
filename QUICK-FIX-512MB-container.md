# Quick Fix for 512MB Container - GC Thrashing

## Your Specific Configuration

**Container Size:** 512MB  
**BBolt Database:** 120MB (memory-mapped)  
**Current Issue:** 300% CPU, 125MB heap memory, heavy GC

## CRITICAL: Memory-Mapped Files Don't Count in Go Heap!

The 120MB BBolt database is memory-mapped, which means:
- ❌ **NOT** included in Go's heap metrics
- ✅ **DOES** consume container memory
- Must account for this when setting GOMEMLIMIT

**Available for Go heap:** 512MB - 120MB (BBolt) - 50MB (OS) = **~340MB**

## IMMEDIATE FIX (Deploy Now)

```bash
# Stop current nuts-node, then restart with:
GOGC=200 GOMEMLIMIT=340MiB ./nuts-node
```

**Why these values:**
- **GOGC=200**: Lets heap grow to 3× (375MB max) before GC triggers
- **GOMEMLIMIT=340MiB**: Safety net accounting for BBolt's 120MB mmap
  - Total memory: 340MB (heap) + 120MB (BBolt) + 50MB (other) = 510MB ✅
- Together: Reduces GC from every 6s to every 10-12s

## Expected Results

**Before:**
- CPU: 300%
- Go Heap: 125MB
- Total Memory: ~300MB (125MB heap + 120MB BBolt + 55MB other)
- GC: Every ~6 seconds
- Errors: Frequent "context canceled"

**After:**
- CPU: **~200-220%** (27-33% improvement)
- Go Heap: **~200-250MB** (still safe under 340MB limit)
- Total Memory: **~370-420MB** (250MB heap + 120MB BBolt + 50MB other)
- GC: Every **~10-12 seconds** (40-50% reduction)
- Errors: **Fewer** (but not eliminated)

## Monitoring

```bash
# Watch Go heap usage (should stay under 340MB)
watch -n 1 'curl -s localhost:8081/metrics | grep go_memstats_heap_alloc_bytes'

# Check total container memory (including BBolt mmap)
# This should show ~370-420MB total
ps aux | grep nuts-node

# Monitor BBolt database size
ls -lh data/vcr/credentials.db

# CRITICAL: If Go heap approaches 300MB+:
# Total would be: 300MB (heap) + 120MB (BBolt) + 50MB = 470MB
# You're getting close to OOM! Take action:
# 1. Lower GOGC to 150 immediately
# 2. Implement caching ASAP (see FIX-GC-thrashing-POC.md)
```

## If This Isn't Enough

The GOGC fix reduces GC frequency but doesn't fix the root cause (allocation churn).

**Next step:** Implement search result caching
- See: `FIX-GC-thrashing-POC.md` Option 2
- Expected: CPU drops from 200% → 100-120%
- Time to implement: 2-4 hours

## Safety Considerations for 512MB Container with 120MB BBolt

**Memory Budget:**
```
Total container:    512MB
BBolt mmap:        -120MB (memory-mapped database)
OS/stack/other:     -50MB
Available for heap: ~340MB (GOMEMLIMIT setting)
```

**Operating ranges:**
- ✅ **Normal operation:** 
  - Go heap: 200-250MB
  - Total: 370-420MB (safe)
  
- ⚠️ **High load:** 
  - Go heap: 280-320MB
  - Total: 450-490MB (approaching limit)
  
- ❌ **Danger zone:** 
  - Go heap: 340MB+
  - Total: 510MB+ → **OOM kill risk!**

**If you consistently hit 300MB+ heap:**
- Option A: **Lower GOGC to 150** (more GC, less memory)
  ```bash
  GOGC=150 GOMEMLIMIT=340MiB ./nuts-node
  ```
- Option B: **Increase container to 1GB** (recommended)
  ```bash
  # With 1GB container:
  GOGC=200 GOMEMLIMIT=780MiB ./nuts-node
  # (1024MB - 120MB BBolt - 50MB other = 854MB, use 780MB to be safe)
  ```
- Option C: **Implement caching NOW** (reduces allocation rate by 75%)
  - See: `FIX-GC-thrashing-POC.md`
  - This is the real fix

## Verification Commands

```bash
# 1. Before starting, check current GC frequency:
GODEBUG=gctrace=1 ./nuts-node 2>&1 | grep "gc " &

# Expected BAD output:
# gc 10 @5.2s: ...
# gc 11 @5.8s: ...  ← Every ~0.6 seconds

# 2. After restart with GOGC=200 GOMEMLIMIT=340MiB:
GODEBUG=gctrace=1 GOGC=200 GOMEMLIMIT=340MiB ./nuts-node 2>&1 | grep "gc " &

# Expected BETTER output:
# gc 10 @5.2s: ...
# gc 11 @6.8s: ...  ← Every ~1.6 seconds (2.7x improvement)
# 
# In gctrace output, look for:
# gc 10 @5.2s 2%: 0.015+10+0.025 ms clock, 200->200->125 MB, 250 MB goal, 4 P
#                                          ^^^^^^^^^^^^^^^^^^
#                                          heap: before->after->live
# Should see "goal" around 340MB (your GOMEMLIMIT)

# 3. Monitor CPU:
top -pid $(pgrep nuts-node)
# Should see CPU drop from 300% to ~200-220% within 5 minutes

# 4. Monitor total memory (RSS - Resident Set Size):
ps aux | grep nuts-node | awk '{print $6/1024 " MB"}'
# Should show 370-420MB total (heap + BBolt + overhead)
# If approaching 500MB, you're in danger zone!
```

## What If It Doesn't Help?

If CPU stays at 300% after 10 minutes:
1. **Check heap hasn't hit 340MB limit** - GC becomes aggressive at limit
2. **Check total memory (RSS)** - should be 370-420MB, not 500MB+
3. **Check GC frequency reduced** - use `GODEBUG=gctrace=1`
4. **The issue may be BBolt lock contention**, not just GC
5. Consider also increasing lock timeout (see ANALYSIS document)

## Risk Assessment

**Medium Risk (due to tight memory constraints):**
- ✅ No code changes required
- ✅ Can be reverted instantly (restart without env vars)
- ⚠️ **340MB GOMEMLIMIT is tight** with 120MB BBolt mmap
- ⚠️ Risk of OOM if heap spikes above 340MB
- ✅ Worst case: No improvement or OOM (easily reverted)

**Monitor for:**
- ⚠️ **Go heap reaching 300MB+** (total would be ~470MB - danger!)
- ⚠️ **Total RSS reaching 480MB+** (approaching OOM)
- ⚠️ **OOM kills** (check `dmesg | grep -i oom`)
- ⚠️ **Longer GC pauses** (check with `GODEBUG=gctrace=1`)
- ⚠️ **BBolt database growing** (check `ls -lh data/vcr/credentials.db`)

**If you see OOM risk (heap > 300MB):**
1. **Immediately revert** to default (restart without GOGC/GOMEMLIMIT)
2. **Implement caching** (Option 2 in FIX-GC-thrashing-POC.md)
3. **Or increase container to 1GB** (gives 780MB for heap)

**Alternative safer configuration (if OOM risk is too high):**
```bash
# More conservative: More frequent GC, but safer memory usage
GOGC=150 GOMEMLIMIT=340MiB ./nuts-node
# This keeps heap under 250MB, total under 420MB
```

