 .. _testing:

Testplan
########

This document describes what (of the Nuts node) we want to test,
which kind of tests we want to have and how they fit in the development cycle (how/when they are run).

Traits
******

We want to test the following traits of the Nuts node:

* Functionality: when an actor performs an operation, is the outcome as expected?
* Security: ...
* Performance
   * Throughput: how many transactions/second can the Nuts node handle?
   * Load test: can the Nuts node handle the minimum expected number of transactions/second?
   * Stress test: does the Nuts node stay responsive under load?
* Scalability: ...

Principles
**********



Testing Pyramid
^^^^^^^^^^^^^^^

High-level (e.g. API tests against a deployed environment) are more expensive to write (complicated, require lots of set-up and teardown)
and maintain (more dependencies means more breakdowns).
Low-level tests (e.g. unit tests) are cheap to write (little setup and teardown) and generally don't breakdown because of external factors.


Low-level tests (unit tests) are the cheapest to write, the fastest to run and the least likely to break,

https://martinfowler.com/articles/practical-test-pyramid.html#TheTestPyramid


Automate Everything
^^^^^^^^^^^^^^^^^^^

Manual tests are tests

Robust tests
^^^^^^^^^^^^

