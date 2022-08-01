.. _nuts-node-monitoring:

Monitoring the Nuts Node
########################

Basic service health
********************

A status endpoint is provided to check if the service is running and if the web server has been started.
The endpoint is available over http so it can be used by a wide range of health checking services.
It does not provide any information on the individual engines running as part of the executable.
The main goal of the service is to give a YES/NO answer for if the service is running?

.. code-block:: text

    GET /status

It'll return an "OK" response and a 200 status code.

Basic diagnostics
*****************

.. code-block:: text

    GET /status/diagnostics

It'll return some text displaying the current status of the various services:

.. code-block:: text

    Status
        Registered engines: [Status Logging]
    Logging
        verbosity: INFO

If you supply ``application/json`` for the ``Accept`` HTTP header it will return the diagnostics in JSON format.

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
          - targets: ['127.0.0.1:1323']

It's important to enter the correct IP/domain and port where the Nuts node can be found!

Exported metrics
================

The Nuts service executable exports the following metric namespaces:

* ``nuts_`` contains metrics related to the functioning of the Nuts node
* ``process_`` contains OS metrics related to the process
* ``go_`` contains Go metrics related to the process
* ``http_`` contains metrics related to HTTP calls to the Nuts node
* ``promhttp_`` contains metrics related to HTTP calls to the Nuts node's ``/metrics`` endpoint

Network DAG Visualization
*************************

All network transactions form a directed acyclic graph (DAG) which helps achieving consistency and data completeness.
Since it's a hard to debug, complex structure, the network API provides a visualization which can be queried
from `/internal/network/v1/diagnostics/graph`. It is returned in the `dot` format which can then be rendered to an image using
`dot` or `graphviz` (given you saved the output to `input.dot`):

.. code-block:: shell

    dot -T png -o output.png input.dot

Using query parameters `start` and `end` it is possible to retrieve a range of transactions.
`/internal/network/v1/diagnostics/graph?start=10&end=12` will return a graph with all transactions containing Lamport Clock 10 and 11.
Both parameters need to be non-negative integers, and `start` < `end`. If no value is provided, `start=0` and `end=inf`.
Querying a range can be useful if only a certain range is of interest, but may also be required to generate the graph using `dot`.

CPU profiling
*************

It's possible to enable CPU profiling by passing the ``--cpuprofile=/some/location.dmp`` option.
This will write a CPU profile to the given location when the node shuts down.
The resulting file can be analyzed with Go tooling:

.. code-block:: shell

    go tool pprof /some/location.dmp

The tooling includes a help function to get you started. To get started use the ``web`` command inside the tooling.
It'll open a SVG in a browser and give an overview of what the node was doing.