# Memory Layout: 512MB Container with 120MB BBolt Database

## Why GOMEMLIMIT Must Be 340MiB (Not 460MiB)

```
┌─────────────────────────────────────────────────────────────┐
│                  512MB Container Memory                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  BBolt Database (Memory-Mapped File)                 │  │
│  │  120MB                                                │  │
│  │  • Not in Go heap                                     │  │
│  │  • Directly mapped to container memory                │  │
│  │  • Counted in RSS (Resident Set Size)                │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  OS + Stack + Network Buffers + Misc                 │  │
│  │  ~50MB                                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Go Heap (Available Memory)                          │  │
│  │  340MB ← GOMEMLIMIT should be set to this            │  │
│  │                                                        │  │
│  │  With GOGC=200:                                       │  │
│  │    Current: 125MB                                     │  │
│  │    Can grow to: ~250MB (2× with GOGC=200)           │  │
│  │    Max before GOMEMLIMIT: 340MB                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Safety Buffer                                        │  │
│  │  2MB                                                  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
  120MB + 50MB + 340MB + 2MB = 512MB ✅
```

## What Happens with Different GOMEMLIMIT Values

### ❌ WRONG: GOMEMLIMIT=460MiB

```
Go Heap grows to:     250MB (normal with GOGC=200)
BBolt mmap:          +120MB
OS/other:             +50MB
Total:                420MB ✅ OK so far

But if heap spikes to 375MB (GOGC=200 max):
Go Heap:              375MB
BBolt mmap:          +120MB
OS/other:             +50MB
Total:                545MB ❌ EXCEEDS 512MB! → OOM KILL
```

### ✅ CORRECT: GOMEMLIMIT=340MiB

```
Go Heap grows to:     250MB (normal with GOGC=200)
BBolt mmap:          +120MB
OS/other:             +50MB
Total:                420MB ✅ SAFE

Even if heap hits limit at 340MB:
Go Heap:              340MB (GOMEMLIMIT prevents further growth)
BBolt mmap:          +120MB
OS/other:             +50MB
Total:                510MB ✅ Still under 512MB (2MB buffer)
```

## Memory Growth Over Time

```
Time →

Container Limit: 512MB ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                                                      ↓ DANGER
BBolt mmap:      120MB ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
OS/other:         50MB ▒▒▒▒▒▒▒▒▒▒▒▒▒▒

                       Current    After     High
                       State      GOGC=200  Load
Go Heap:               125MB      250MB     320MB
                       ████       ████████  ███████████
                       
Total Memory:          295MB      420MB     490MB
                       ✅ OK      ✅ SAFE   ⚠️ CLOSE

GOMEMLIMIT=340MiB:    ─────────────────────────────▲
                                                     │
                                           Stops heap growth here
```

## Real-World Operating Ranges

### Normal Operation (Expected)
```
Go Heap:     200-250MB  ✅
BBolt:       120MB      (constant)
Other:       50MB       (constant)
─────────────────────
Total:       370-420MB  ✅ Safe (80-82% of container)
```

### High Load (Acceptable)
```
Go Heap:     280-320MB  ⚠️
BBolt:       120MB      (constant)
Other:       50MB       (constant)
─────────────────────
Total:       450-490MB  ⚠️ Approaching limit (88-96% of container)
```

### Danger Zone (Take Action!)
```
Go Heap:     340MB+     ❌ GOMEMLIMIT hit, aggressive GC
BBolt:       120MB      (constant)
Other:       50MB       (constant)
─────────────────────
Total:       510MB+     ❌ OOM risk! (99%+ of container)

Action: Revert to default or implement caching immediately
```

## Why BBolt mmap Doesn't Count in Go Heap

```
┌──────────────────────────────────────┐
│  Operating System View (RSS)         │
│                                       │
│  Total = 420MB                        │
│    ├─ 250MB Go heap                  │
│    ├─ 120MB BBolt mmap               │
│    └─  50MB other                    │
└──────────────────────────────────────┘
         ↓               ↓
         ↓               ↓
┌─────────────────┐    ┌──────────────────┐
│  Go Runtime     │    │  OS Kernel       │
│  Sees: 250MB    │    │  Sees: 420MB     │
│  (heap only)    │    │  (total RSS)     │
└─────────────────┘    └──────────────────┘
         ↓                       ↓
         ↓                       ↓
    GOMEMLIMIT              OOM Killer
    triggers at             triggers at
    340MB heap              512MB total
```

Memory-mapped files (mmap) are:
- ✅ Directly mapped to physical memory
- ✅ Counted in process RSS (Resident Set Size)
- ✅ Subject to OOM killer limits
- ❌ NOT allocated from Go heap
- ❌ NOT counted in `go_memstats_heap_alloc_bytes`
- ❌ NOT subject to GOMEMLIMIT (directly)

## Summary

**For 512MB container with 120MB BBolt:**

```bash
# CORRECT configuration:
GOGC=200 GOMEMLIMIT=340MiB ./nuts-node
```

**Math:**
- Container: 512MB
- BBolt mmap: -120MB (outside Go control)
- OS/other: -50MB (outside Go control)
- Available for Go heap: **340MB** ← This is your GOMEMLIMIT
- Safety buffer: 2MB

**Never exceed 340MB Go heap**, or you risk:
```
340MB (heap) + 120MB (BBolt) + 50MB (other) = 510MB → OOM at 512MB!
```

