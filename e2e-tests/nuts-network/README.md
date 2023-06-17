This test suite tests the Nuts Network. It tests the following cases:

1. Direct-WAN: Node B directly connects to Node A, no SSL/TLS offloading.
2. SSL-Offloading: Node B connects to Node A which uses SSL/TLS offloading (e.g. layer 7 load balancing).
2. SSL-Pass-through: Node B connects to Node A which uses SSL/TLS pass-through (e.g. layer 5 load balancing).