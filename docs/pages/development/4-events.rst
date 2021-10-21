Events
******

Each event consists of a single JSON encoded message that is categorized by its subject which in term are grouped into streams.
Each stream defines how to handle limits, storage, data retention, deliverability etc.

Streams
-------

======================== ============================================================================== ======= ============= ==========
Name                     Summary                                                                        Durable Message limit Storage
======================== ============================================================================== ======= ============= ==========
nuts-private-credentials Messages need to be acked, when the stream is full new messages will be denied Yes     10            Filesystem
nuts-disposable          When the stream is full old messages will be discarded                         No      100           Memory


Events
------

========================= ======================== =============================
Event                     Stream                   Description
========================= ======================== =============================
nuts.vcr.private.exchange nuts-private-credentials Exchange a private credential
