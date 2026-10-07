This test suite tests the Nuts Network. It tests the following cases:

1. Direct-WAN: Node B directly connects to Node A, no SSL/TLS offloading.
2. SSL-Offloading: Node B connects to Node A which uses SSL/TLS offloading (e.g. layer 7 load balancing).
2. SSL-Pass-through: Node B connects to Node A which uses SSL/TLS pass-through (e.g. layer 5 load balancing).
4. SQL-storage: Node A and B start on bbolt, are switched to the key-value stores (DAG, DID store, notifier jobs,
   credential backups) on SQL (`storage.kv.backend=sql`, importing the bbolt data), once per supported database
   (PostgreSQL, MySQL, SQL Server). Covers public transactions, private credentials, revocations and restarts.
