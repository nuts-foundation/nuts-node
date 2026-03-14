# Proof of Concept Fix: GC Thrashing in VCR Search

## Problem Statement

With 125MB memory and heavy GC, the issue is **allocation churn**:
- 4 parallel searches every 2 seconds
- Each search allocates ~1MB of short-lived objects
- = 2-10MB/second allocation rate
- = GC running constantly
- = 20-30% CPU wasted on GC

## Immediate Fix Options (Pick One or Both)

### Option 1: Increase GOGC + Set GOMEMLIMIT (Quickest - No Code Change)

**Action:** Set environment variables before starting nuts-node:

```bash
# RECOMMENDED: Combine both for safety
GOGC=200 GOMEMLIMIT=1GiB ./nuts-node

# How to calculate GOMEMLIMIT:
# GOMEMLIMIT = (container_memory - mmap_files - os_overhead)
# 
# IMPORTANT: If you use BBolt with memory-mapped files, account for them!
# BBolt databases are mmap'd and consume container memory but NOT Go heap.
#
# Examples (assuming NO large mmap files):
#   512MB container: GOMEMLIMIT=460MiB
#   1GB container:   GOMEMLIMIT=900MiB
#   2GB container:   GOMEMLIMIT=1800MiB
#   4GB container:   GOMEMLIMIT=3600MiB
#
# Examples WITH 120MB BBolt database (memory-mapped):
#   512MB container: GOMEMLIMIT=340MiB  (512 - 120 - 50 = 342)
#   1GB container:   GOMEMLIMIT=780MiB  (1024 - 120 - 124 = 780)
#   2GB container:   GOMEMLIMIT=1700MiB (2048 - 120 - 228 = 1700)

# More aggressive (if you have lots of RAM):
GOGC=300 GOMEMLIMIT=2GiB ./nuts-node
```

**How They Work Together:**

- **GOGC=200**: Reduces GC frequency by letting heap grow to 3× before triggering
  - Current: 125MB → GC at 250MB (GOGC=100)
  - With GOGC=200: 125MB → GC at 375MB
  - Result: GC runs half as often

- **GOMEMLIMIT=1GiB**: Safety net preventing OOM
  - If heap approaches 1GB, GC becomes aggressive
  - Prevents runaway allocation from crashing the node
  - In practice, you'll stay well under this with normal traffic

**Expected Result:**
- GC frequency drops from every 6s to every 12-18s
- GC CPU overhead drops from 20-30% to 5-10%
- Heap size grows from 125MB to ~250-300MB (acceptable tradeoff)
- **Should reduce CPU from 300% to ~200%**
- Protected from OOM by GOMEMLIMIT safety net

**Risks:**
- Slightly higher memory usage (250-300MB vs 125MB)
- Longer GC pause times when they do occur (but much less frequent)
- Doesn't fix root cause (allocation churn)

**Why Both?**
- GOGC alone: Reduces GC frequency but no safety net
- GOMEMLIMIT alone: Doesn't reduce normal GC frequency enough
- **Together**: Best of both worlds - less GC + OOM protection

---

### Option 2: Add Simple Search Cache (Recommended)

**File:** `vcr/vcr.go` - Add cache fields to the vcr struct

```go
import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
)

type vcr struct {
    // ...existing fields...
    
    // Add these:
    searchCache    sync.Map
    searchCacheTTL time.Duration
}
```

**File:** `vcr/vcr.go` - Initialize in NewVCR:

```go
func NewVCR(...) VCR {
    instance := &vcr{
        // ...existing fields...
        searchCacheTTL: 2 * time.Second,  // Match the request frequency
    }
    // ...rest of initialization...
}
```

**File:** `vcr/search.go` - Add caching logic:

```go
// Add at top of file
import (
    "crypto/sha256"
    "encoding/hex"
)

type searchCacheEntry struct {
    results   []vc.VerifiableCredential
    timestamp time.Time
}

// Add cache key generation
func generateSearchCacheKey(searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) string {
    hasher := sha256.New()
    
    // Hash search terms
    for _, term := range searchTerms {
        hasher.Write([]byte(strings.Join(term.IRIPath, "/")))
        hasher.Write([]byte(term.Type))
        hasher.Write([]byte(fmt.Sprintf("%v", term.Value)))
    }
    
    // Hash flags
    if allowUntrusted {
        hasher.Write([]byte("untrusted"))
    }
    if resolveTime != nil {
        hasher.Write([]byte(resolveTime.Format(time.RFC3339)))
    }
    
    return hex.EncodeToString(hasher.Sum(nil))
}

// Modify Search function
func (c *vcr) Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error) {
    // Generate cache key
    cacheKey := generateSearchCacheKey(searchTerms, allowUntrusted, resolveTime)
    
    // Check cache
    if entry, ok := c.searchCache.Load(cacheKey); ok {
        cached := entry.(searchCacheEntry)
        if time.Since(cached.timestamp) < c.searchCacheTTL {
            log.Logger().Debug("Returning cached search results")
            return cached.results, nil  // Cache hit - NO ALLOCATIONS!
        }
        // Expired, remove from cache
        c.searchCache.Delete(cacheKey)
    }
    
    // Cache miss - proceed with normal search
    query := leia.Query{}
    var VCs = make([]vc.VerifiableCredential, 0)

    // ...existing query building code...

    docs, err := c.credentialCollection().Find(ctx, query)
    if err != nil {
        return nil, err
    }
    
    // ...existing verification loop...
    
    // Store in cache before returning
    c.searchCache.Store(cacheKey, searchCacheEntry{
        results:   VCs,
        timestamp: time.Now(),
    })
    
    return VCs, nil
}
```

**Expected Result:**
- First of 4 parallel searches: Cache miss → 1MB allocation → stores in cache
- Next 3 parallel searches: Cache hit → **0 allocations** → instant return
- Next request 2s later: Cache still valid → cache hit → 0 allocations
- **Allocation rate drops from 2MB/s to ~0.5MB/s (75% reduction)**
- **GC frequency drops by 75%**
- **CPU should drop from 300% to ~150%**

---

### Option 3: Pre-allocate with Capacity (Complementary)

**File:** `vcr/search.go` - Simple optimization:

```go
func (c *vcr) Search(ctx context.Context, searchTerms []SearchTerm, allowUntrusted bool, resolveTime *time.Time) ([]vc.VerifiableCredential, error) {
    // ...cache check...
    
    query := leia.Query{}
    
    // Pre-fetch document count if possible, or estimate
    docs, err := c.credentialCollection().Find(ctx, query)
    if err != nil {
        return nil, err
    }
    
    // Pre-allocate slice with capacity to avoid reallocations
    VCs = make([]vc.VerifiableCredential, 0, len(docs))  // ← CHANGE THIS LINE
    
    verifyErrors := make(map[string]int, len(docs)/10)  // ← ESTIMATE CAPACITY
    
    for _, doc := range docs {
        // ...existing code...
    }
}
```

**Expected Result:**
- Eliminates slice reallocation overhead
- Reduces allocations by ~10%
- Small but easy win

---

## Implementation Priority

**Day 1 (Zero code change):**
```bash
# Recommended: Set both GOGC and GOMEMLIMIT
GOGC=200 GOMEMLIMIT=1GiB ./nuts-node

# Or if you know your container size:
# For 512MB container:
GOGC=200 GOMEMLIMIT=460MiB ./nuts-node

# For 1GB container:
GOGC=200 GOMEMLIMIT=900MiB ./nuts-node

# For 2GB container:
GOGC=200 GOMEMLIMIT=1800MiB ./nuts-node

# For 4GB container:
GOGC=200 GOMEMLIMIT=3600MiB ./nuts-node
```
Expected: CPU drops from 300% to ~200%

**Week 1 (Add caching):**
- Implement Option 2 (search cache)
- Expected: CPU drops from 200% to ~100-150%

**Week 2 (Optimize):**
- Add pre-allocation (Option 3)
- Add object pooling
- Expected: CPU drops to ~80-100%

**Week 3+ (Long-term):**
- Review client parallelism
- Consider database migration
- Add comprehensive monitoring

---

## How to Verify the Fix

### Before Fix:
```bash
# Monitor GC
GODEBUG=gctrace=1 ./nuts-node 2>&1 | grep "gc " | head -20

# Expected bad output:
gc 10 @5.2s: ...
gc 11 @5.8s: ...  ← GC every ~0.6 seconds
gc 12 @6.4s: ...
```

### After Fix (GOGC=200):
```bash
# Expected better output:
gc 10 @5.2s: ...
gc 11 @6.5s: ...  ← GC every ~1.3 seconds (2x improvement)
gc 12 @7.8s: ...
```

### After Fix (With Caching):
```bash
# Expected best output:
gc 10 @5.2s: ...
gc 11 @8.0s: ...  ← GC every ~2.8 seconds (4x improvement)
gc 12 @10.8s: ...
```

---

## Cache Eviction Strategy (Optional Enhancement)

To prevent unbounded cache growth:

```go
type searchCacheEntry struct {
    results   []vc.VerifiableCredential
    timestamp time.Time
    accessCount uint32
}

// Add periodic cleanup goroutine
func (c *vcr) startCacheCleanup() {
    ticker := time.NewTicker(10 * time.Second)
    go func() {
        for range ticker.C {
            now := time.Now()
            c.searchCache.Range(func(key, value interface{}) bool {
                entry := value.(searchCacheEntry)
                if now.Sub(entry.timestamp) > c.searchCacheTTL * 5 {  // 5x TTL
                    c.searchCache.Delete(key)
                }
                return true
            })
        }
    }()
}
```

---

## Why This Works

**Current state (BAD):**
```
4 parallel searches arrive → Each allocates 1MB → 4MB total
GC sees 4MB new allocations → triggers GC
Next 4 searches arrive → allocate 4MB → GC again
= Constant GC, 2MB/s allocation rate
```

**With cache (GOOD):**
```
4 parallel searches arrive:
  Search 1: Cache miss → allocate 1MB → store in cache
  Search 2: Cache HIT → return cached → 0 allocations
  Search 3: Cache HIT → return cached → 0 allocations
  Search 4: Cache HIT → return cached → 0 allocations
= 1MB allocated instead of 4MB (75% reduction)

Next request 2s later:
  All 4: Cache HIT → 0 allocations
= 0MB allocated instead of 4MB (100% reduction)

Allocation rate: 1MB / 4 seconds = 0.25MB/s (87.5% reduction!)
```

**With 10 concurrent clients:**
- Before: 10 × 2MB/s = 20MB/s → GC every 6s
- After cache: 10 × 0.25MB/s = 2.5MB/s → GC every 48s
- **8x reduction in GC frequency**
- **80-90% reduction in GC CPU overhead**

---

## Testing Commands

```bash
# 1. Baseline with GC tracing
GODEBUG=gctrace=1 ./nuts-node 2>&1 | tee baseline-gc.log

# 2. Test with GOGC + GOMEMLIMIT
GODEBUG=gctrace=1 GOGC=200 GOMEMLIMIT=1GiB ./nuts-node 2>&1 | tee gogc200-gc.log

# 3. Compare GC frequency
echo "Baseline GC frequency:"
grep "gc " baseline-gc.log | wc -l
echo "With GOGC=200 + GOMEMLIMIT:"
grep "gc " gogc200-gc.log | wc -l

# 4. Monitor memory usage to ensure we don't hit GOMEMLIMIT
watch -n 1 'curl -s localhost:8081/metrics | grep -E "go_memstats_heap_alloc_bytes|go_memory_limit_bytes"'

# 5. Monitor CPU during load
top -pid $(pgrep nuts-node) -stats pid,cpu,mem,time

# 6. Watch GC and allocation metrics in real-time
watch -n 1 'curl -s localhost:8081/metrics | grep -E "(alloc_bytes|gc_duration|memory_limit)"'
```

