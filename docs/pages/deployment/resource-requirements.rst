.. _resource-requirements:

Resource Requirements
#####################

The Nuts node is built to be lightweight in terms of CPU and memory usage. Proof: it even runs on a Raspberry PI (Zero).

For a production environment you should be able to run it on a small cloud VM, which typically start at;

- 1 CPU
- 512 MB RAM
- 25 GB storage

Required storage depends on network state which grows over time, so make sure to monitor it.

If you use Redis for network state storage the storage requirements will be lower,
but since search indexes are kept on disk it will still grow over time (although at a lower rate).
