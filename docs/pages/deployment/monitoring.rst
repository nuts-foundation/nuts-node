.. _nuts-node-monitoring:

Monitoring
##########

Health checks
*************

Health
------

An endpoint is provided to perform health checks on the Nuts node.
It reports in a format compatible with `Spring Boot's Health Actuator <https://docs.spring.io/spring-boot/docs/2.0.x/actuator-api/html/#health>`__.
The endpoint is available over HTTP:

.. code-block:: text

    GET /health

Each component in the health check can have one of the statuses ``UP``, ``UNKNOWN``, or ``DOWN``.
The overall status is determined by the lowest common denominator, so if one components is ``DOWN``, the overall system status is ``DOWN``.
The overall system statuses ``UP`` and ``UNKNOWN`` map to HTTP status code ``200``, and status ``DOWN`` maps to status code ``503``.

Example response when all checks succeeded (formatted for readability):

.. code-block:: json

    {
      "status": "UP",
      "details": {
        "crypto.filesystem": {
          "status": "UP"
        },
        "network.auth_config": {
          "status": "UP",
          "details": "no node DID"
        },
        "network.tls": {
          "status": "UP"
        }
      }
    }

Example response when one or more checks failed:

.. code-block:: json

    {
      "status": "DOWN",
      "details": {
        "network.tls": {
          "status": "DOWN",
          "details": "x509: certificate signed by unknown authority"
        }
      }
    }

.. note::

    The provided Docker containers are configured to perform this healthcheck out of the box.
    However, if the internal endpoints port (:8081) has been changed, the healthcheck will fail and Docker will mark the container as unhealthy.
    Override the default healthcheck to solve this.

Status
------

There's also a status endpoint to check whether the service has been started.
It does not provide any information on the individual engines running as part of the executable.
The main goal of the service is to give a YES/NO answer for if the service is running:

.. code-block:: text

    GET /status

Returns an "OK" response body with status code ``200``.

Basic diagnostics
*****************

.. code-block:: text

    GET /status/diagnostics

Returns the status of the various services in ``yaml`` format:

.. code-block:: text

    network:
        connections:
            connected_peers:
                - id: d38c6df5-63d2-4b2c-87f4-2e8bbfa5612f
                  address: nuts.nl:5555
                  nodedid: did:nuts:abc123
            connected_peers_count: 1
        state:
            dag_xor: 6aada4464e380db16d0316e597956fcdaeada0e8f6023be82eeb9c798e1815c6
            stored_database_size_bytes: 106496005
            transaction_count: 9001
    vcr:
        credential_count: 7
        issuer:
            issued_credentials_count: 0
            revoked_credentials_count: 0
        verifier:
            revocations_count: 18
    vdr:
        did_documents_count: 5
        conflicted_did_documents:
            total_count: 2
            owned_count: 0
    status:
        git_commit: d36837bae48b780bfb76134e85b506472fc207a6
        os_arch: linux/amd64
        software_version: master
        uptime: 4h14m12s

If you supply ``application/json`` for the ``Accept`` HTTP header it will return the diagnostics in JSON format.

Explanation of ambiguous/complex entries in the diagnostics:

* ``vcr.credential_count`` holds the total number of credentials known to the node (public VCs, and private VCs issued to a DID on the local node)
* ``vcr.issuer.issued_credentials_count`` holds the total number of credentials issued by the local node
* ``vcr.issuer.revoked_credentials_count`` holds the total number of revoked credentials issued by the local node
* ``vcr.verifier.revocations_count`` holds the total number of revoked credentials (public and private VCs)
* ``vdr.conflicted_did_documents.total_count`` holds the total number of DID documents that are conflicted (have parallel updates). This may indicate a stolen private key
* ``vdr.conflicted_did_documents.owned_count`` holds the number of conflicted DID documents you control as a node owner

Note: the ``network`` and ``vdr`` entries only apply to ``did:nuts``.

Metrics
*******

The Nuts service executable has build-in support for **Prometheus**. Prometheus is a time-series database which supports a wide variety of services. It also allows for exporting metrics to different visualization solutions like **Grafana**. See https://prometheus.io/ for more information on how to run Prometheus. The metrics are exposed at ``/metrics``

Configuration
=============

In order for metrics to be gathered by Prometheus. A ``job`` has to be added to the ``prometheus.yml`` configuration file.
Below is a minimal configuration file that will only gather Nuts metrics:

.. code-block:: yaml

    # my global config
    global:
      scrape_interval:     15s # Set the scrape interval to every 15 seconds. Default is every 1 minute.
      evaluation_interval: 15s # Evaluate rules every 15 seconds. The default is every 1 minute.
      # scrape_timeout is set to the global default (10s).

    # Load rules once and periodically evaluate them according to the global 'evaluation_interval'.
    rule_files:
    # - "first_rules.yml"
    # - "second_rules.yml"

    # A scrape configuration containing exactly one endpoint to scrape:
    scrape_configs:
      # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
      - job_name: 'nuts'
        metrics_path: '/metrics'
        scrape_interval: 5s
        static_configs:
          - targets: ['127.0.0.1:8081']

It's important to enter the correct IP/domain and port where the Nuts node can be found!

Exported metrics
================

The Nuts service executable exports the following metric namespaces:

* ``nuts_`` contains metrics related to the functioning of the Nuts node
* ``process_`` contains OS metrics related to the process
* ``go_`` contains Go metrics related to the process
* ``promhttp_`` contains metrics related to HTTP calls to the Nuts node's ``/metrics`` endpoint

CPU profiling
*************

It's possible to enable CPU profiling by passing the ``--cpuprofile=/some/location.dmp`` option.
This will write a CPU profile to the given location when the node shuts down.
The resulting file can be analyzed with Go tooling:

.. code-block:: shell

    go tool pprof /some/location.dmp

The tooling includes a help function to get you started. To get started use the ``web`` command inside the tooling.
It'll open a SVG in a browser and give an overview of what the node was doing.
