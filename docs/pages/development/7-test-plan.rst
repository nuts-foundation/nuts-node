 .. _test-plan:

Test Plan
#############

This document describes what (of the Nuts node) we want to test,
how we test it and how they fit in the development cycle (how/when they are run).

Next steps:

1. Review test overview, add missing test targets
2. Review untested parts, decide what parts need to be (structurally) tested
3. Make plan for testing the untested parts. This will probably involve specifying tests that need to be performed on release candidates.

Architecture
************

We want to test the following traits of the Nuts node:

* Functionality: when an actor performs an operation, is the outcome as expected?
* Security: do security measures work as intended?
* Performance
   * Throughput: how many transactions/second can the Nuts node handle?
   * Load test: can the Nuts node handle the minimum expected number of transactions/second?
   * Stress test: does the Nuts node stay responsive under load?
* Compliance: does the Nuts node comply with the `Nuts specification <https://nuts-foundation.gitbook.io/drafts/>`_?
* Compatibility: does the Nuts node work with other versions of Nuts node?
* Upgradeability: can the Nuts node and its data be upgraded to a newer version without breaking down or data loss?

Layers
^^^^^^

This section lists the layers of the Nuts node. Each layer represents a testing target.

* Clients:
   * CLI interface: used by operators for administration, uses the HTTP client.
   * HTTP clients: used by the CLI interface to communicate with the HTTP API, partly generated.
* API:
   * HTTP APIs: used by clients (CLI, other sytems/Nuts nodes), intermediate layer to translate HTTP calls to business logic invocations.
   * gRPC Protocol: used by other Nuts nodes to exchange network state.
* Services:
   * Modules: cohesive collection of functions performing business logic.
   * Backing functions: implementation details of to perform business logic.
* Resources:
   * Backing resources: external resources invoked or consumed by business logic,
     e.g. databases, secret stores, X.509 CRLs, authentication providers (IRMA), etc.

Types of tests
^^^^^^^^^^^^^^

The following types of tests are employed regularly in the Nuts node:

* Unit test: automated Go unit tests, testing a single unit of code. Generally mocks its dependencies.
* Integration test: like a unit test, but with backing functions, no mocked behavior.
  Uses actual backing resources (e.g. in-memory database).
* End-to-end (e2e) test: automated tests the deployed systems using external interfaces (HTTP APIs).
  Deploys using Docker Compose and performs tests using Bash scripts.

The following types of tests are performed on-demand and are generally unstructured:

* Manual test: high-level test (often one-off) performed by a human, testing a specific feature or characteristic, e.g.:
   * testing a newly developed feature
   * testing whether IRMA authentication still works
   * testing the integration of Demo EHR/Registry Admin
   * testing data migration when updating the Nuts node
* Performance test: assert that the system can reach a certain throughput, or that it stays responsive under load.

Test Coverage
*************

This section describes how these traits and layers are covered by tests.

.. list-table:: Tests
    :header-rows: 1

    * - Layer
      - Test coverage
      - Remarks
    * - CLI interface
      - Unit tests
    * - HTTP client
      - Unit tests
    * - HTTP API
      - - Unit tests
        - Integration test (asserts HTTP response codes)
    * - gRPC Protocol
      - - Unit tests
        - Integration tests
    * Module: Main
      - Integration test for testing boot/shutdown behavior
    * - Module: Auth
      - - Unit tests
        - e2e test for OAuth flow
    * - Module: Crypto
      - Unit tests
    * - Module: Didman
      - Unit tests
    * - Module: Network
      - - Unit tests
        - Integration test for general node behavior
        - Integration test for v2 protocol edge cases
        - e2e test for TLS offloading layouts
        - e2e test for private transactions
        - e2e test for transaction gossip
    * - Module: VDR
      - - Unit tests
        - Integration test for DID store behavior
        - Integration test for VDR behavior
    * - Module: VCR
      - Unit tests
    * - Backing functions
      - Unit tests
    * - Backing resources: IRMA
      - Unit tests
    * - Backing resources: Hashicorp Vault Proxy for key storage
      - e2e test for testing integration with Nuts node
    * - Backing resources: BBolt
      - Unit tests
      - e2e test for happy paths
      - e2e test for backup/restore functionality
    * - Backing resources: Redis
      - Unit tests
      - e2e test for happy path

.. note::

    Discuss: why do some modules have integration tests, while others don't?
    E.g., why does VDR have them, but VCR doesn't?

Uncovered Parts
^^^^^^^^^^^^^^^

The following parts (functionality, systems, resources, traits, etc) are not covered by (structured) testing:

* Data access flow with IRMA authenticated user identity
* Integration with Demo EHR
* Integration with Registry Admin Demo
* JWT Generator application
* Data Viewer application
* Performance
* Security, especially the negative cases:
   * TLS certificates (untrusted/revoked certificates)
   * Protected access to internal endpoints (e.g. API authentication, HTTP interface binding)
* Compatibility of the current release with the last release and previous major release
* Compliance
* Upgradeability to the next major release without loss of data

.. note::

    We need to discuss whether these parts need to be covered by structured testing.

Principles
**********

This section describes what principles should be applied when testing or writing (automated) tests.

Testing Pyramid
^^^^^^^^^^^^^^^

High-level (e.g. API tests against a deployed environment) are more expensive to write (complicated, require lots of set-up and teardown)
and maintain (more dependencies means more breakdowns).
Low-level tests (e.g. unit tests) are cheap to write (little setup and teardown) and generally don't breakdown because of external factors.
This is known as the `Test Pyramid <https://martinfowler.com/articles/practical-test-pyramid.html#TheTestPyramid>`_.

Actions:

* Use unit tests to component(e.g. Golang struct) behavior and business logic (e.g. validation).
* Use integration tests (Golang tests) to test interaction between components (e.g. with backing resources, e.g. database).
  Don't use external resources (e.g. X.509 CRLs) in these tests, since these make the tests flippy.
* Use end-to-end tests to verify functionality in a deployed environment.

Automation
^^^^^^^^^^

Manual tests are often forgotten (or skipped), especially when schedules are tight.

Actions:

* Tests should be automated as much as possible and run automatically.

Robust tests
^^^^^^^^^^^^

When tests are flippy people tend to attribute breakdowns to the testing environment, potentially ignoring actual bugs.

Actions:

* Treat flippy test as bug first, rather than a testing environment issue.
* Make flippy tests, caused by the environment, more robust.

Testing shows presence of defects
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Not the absence. Do not rely for automated tests to test a new feature, manually test it yourself.
For the same reason, the developer of a feature shouldn't be the one testing it:
they know too much about its implementation, and could miss obvious defects or edge (but still relevant) cases.

Action: ask someone else to test the feature you developed.

Absence of Error Fallacy
^^^^^^^^^^^^^^^^^^^^^^^^

When all tests pass, it doesn't necessarily mean that the software is usable or meet the requirements.

Action: when (manually) testing a feature, start from the user/requirements perspective (rather than the implementation perspective).