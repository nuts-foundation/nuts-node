Events
******

Each event consists of a single JSON encoded message that is categorized by its subject which in term are grouped into streams.
Each stream defines how to handle limits, storage, data retention, deliverability etc.

Streams
-------

======================== ================= ============================================================================== ======= ============= =======
Name                     Summary           Policy                                                                         Durable Message limit Storage
======================== ================= ============================================================================== ======= ============= =======
nuts-disposable          Main event-stream When the stream is full old messages will be discarded                         No      100           Memory
