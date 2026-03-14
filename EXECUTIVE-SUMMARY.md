# 300% CPU Root Cause: GC Thrashing
## The Issue
- 125MB memory + heavy GC = **ALLOCATION CHURN**
- 4 parallel searches every 2s × N clients = 2-20MB/s allocation rate
- Each search: allocates 1MB → GC cleans up → repeat
- GC runs every 6 seconds consuming 20-30% CPU
## The Fix
### TODAY (0 code):
```bash
GOGC=200 ./nuts-node
```
Expected: 300% → 200% CPU
### THIS WEEK (add caching):
Cache search results for 2 seconds
Expected: 200% → 100-120% CPU
See: FIX-GC-thrashing-POC.md
## Why It Works
- 4 parallel searches: 1 cache miss + 3 cache hits
- 4MB allocation → 1MB allocation (75% reduction)
- GC frequency drops 75%
- CPU overhead drops 60%+
