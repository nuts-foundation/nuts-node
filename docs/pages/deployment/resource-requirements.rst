.. _resource-requirements:

Resource Requirements
#####################

The Nuts node is built to be lightweight in terms of CPU and memory usage.

The minimum system for **development** and **test** are:

- 1 CPU
- 512 MB RAM
- 25 GB storage

Recommended system requirements for production depends on the expected load and use cases.
It's recommended to keep track of the system's performance and adjust the resources accordingly.
CPU and memory usage, and the API response times are good indicators of the system's performance.
Make sure the CPUs are of a decent speed, as some operations are CPU-bound.
The exposes metrics for ``process_cpu_seconds_total``, ``go_gc_duration_seconds_sum`` and ``go_memstats_alloc_bytes`` are a good starting point for monitoring CPU and memory usage.

If you make heavy use of NutsAuthorizationCredentials, a minimum of 4 CPUs is recommended.

Required storage depends on network state which grows over time, so make sure to monitor it.

If you use Redis for network state storage the storage requirements will be lower,
but since search indexes are kept on disk it will still grow over time (although at a lower rate).
