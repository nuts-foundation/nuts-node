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

Example output:

.. code-block:: text

    # HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
    # TYPE go_gc_duration_seconds summary
    go_gc_duration_seconds{quantile="0"} 4.1374e-05
    go_gc_duration_seconds{quantile="0.25"} 4.832e-05
    go_gc_duration_seconds{quantile="0.5"} 5.9104e-05
    go_gc_duration_seconds{quantile="0.75"} 8.2037e-05
    go_gc_duration_seconds{quantile="1"} 0.000107171
    go_gc_duration_seconds_sum 0.000867003
    go_gc_duration_seconds_count 13
    # HELP go_goroutines Number of goroutines that currently exist.
    # TYPE go_goroutines gauge
    go_goroutines 51
    # HELP go_info Information about the Go environment.
    # TYPE go_info gauge
    go_info{version="go1.18"} 1
    # HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
    # TYPE go_memstats_alloc_bytes gauge
    go_memstats_alloc_bytes 9.623776e+06
    # HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.
    # TYPE go_memstats_alloc_bytes_total counter
    go_memstats_alloc_bytes_total 5.0023112e+07
    # HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table.
    # TYPE go_memstats_buck_hash_sys_bytes gauge
    go_memstats_buck_hash_sys_bytes 1.481901e+06
    # HELP go_memstats_frees_total Total number of frees.
    # TYPE go_memstats_frees_total counter
    go_memstats_frees_total 448490
    # HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata.
    # TYPE go_memstats_gc_sys_bytes gauge
    go_memstats_gc_sys_bytes 5.737688e+06
    # HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.
    # TYPE go_memstats_heap_alloc_bytes gauge
    go_memstats_heap_alloc_bytes 9.623776e+06
    # HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used.
    # TYPE go_memstats_heap_idle_bytes gauge
    go_memstats_heap_idle_bytes 5.963776e+06
    # HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use.
    # TYPE go_memstats_heap_inuse_bytes gauge
    go_memstats_heap_inuse_bytes 1.2812288e+07
    # HELP go_memstats_heap_objects Number of allocated objects.
    # TYPE go_memstats_heap_objects gauge
    go_memstats_heap_objects 77018
    # HELP go_memstats_heap_released_bytes Number of heap bytes released to OS.
    # TYPE go_memstats_heap_released_bytes gauge
    go_memstats_heap_released_bytes 3.60448e+06
    # HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system.
    # TYPE go_memstats_heap_sys_bytes gauge
    go_memstats_heap_sys_bytes 1.8776064e+07
    # HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
    # TYPE go_memstats_last_gc_time_seconds gauge
    go_memstats_last_gc_time_seconds 1.659085950149366e+09
    # HELP go_memstats_lookups_total Total number of pointer lookups.
    # TYPE go_memstats_lookups_total counter
    go_memstats_lookups_total 0
    # HELP go_memstats_mallocs_total Total number of mallocs.
    # TYPE go_memstats_mallocs_total counter
    go_memstats_mallocs_total 525508
    # HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures.
    # TYPE go_memstats_mcache_inuse_bytes gauge
    go_memstats_mcache_inuse_bytes 14400
    # HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system.
    # TYPE go_memstats_mcache_sys_bytes gauge
    go_memstats_mcache_sys_bytes 15600
    # HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures.
    # TYPE go_memstats_mspan_inuse_bytes gauge
    go_memstats_mspan_inuse_bytes 324360
    # HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system.
    # TYPE go_memstats_mspan_sys_bytes gauge
    go_memstats_mspan_sys_bytes 375360
    # HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place.
    # TYPE go_memstats_next_gc_bytes gauge
    go_memstats_next_gc_bytes 1.3709824e+07
    # HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations.
    # TYPE go_memstats_other_sys_bytes gauge
    go_memstats_other_sys_bytes 2.696019e+06
    # HELP go_memstats_stack_inuse_bytes Number of bytes in use by the stack allocator.
    # TYPE go_memstats_stack_inuse_bytes gauge
    go_memstats_stack_inuse_bytes 2.195456e+06
    # HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator.
    # TYPE go_memstats_stack_sys_bytes gauge
    go_memstats_stack_sys_bytes 2.195456e+06
    # HELP go_memstats_sys_bytes Number of bytes obtained from system.
    # TYPE go_memstats_sys_bytes gauge
    go_memstats_sys_bytes 3.1278088e+07
    # HELP go_threads Number of OS threads created.
    # TYPE go_threads gauge
    go_threads 19
    # HELP http_request_duration_seconds The HTTP request latencies in seconds.
    # TYPE http_request_duration_seconds histogram
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="0.005"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="0.01"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="0.025"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="0.05"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="0.1"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="0.25"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="0.5"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="1"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="2.5"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="5"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="10"} 1
    http_request_duration_seconds_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="+Inf"} 1
    http_request_duration_seconds_sum{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice"} 0.000206011
    http_request_duration_seconds_count{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice"} 1
    # HELP http_request_size_bytes The HTTP request sizes in bytes.
    # TYPE http_request_size_bytes histogram
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="1024"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="2048"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="5120"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="10240"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="102400"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="512000"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="1.048576e+06"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="2.62144e+06"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="5.24288e+06"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="1.048576e+07"} 1
    http_request_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="+Inf"} 1
    http_request_size_bytes_sum{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice"} 232
    http_request_size_bytes_count{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice"} 1
    # HELP http_requests_total How many HTTP requests processed, partitioned by status code and HTTP method.
    # TYPE http_requests_total counter
    http_requests_total{code="500",host="localhost:1323",method="GET",url="/internal/didman/v1/did/:did/compoundservice"} 1
    # HELP http_response_size_bytes The HTTP response sizes in bytes.
    # TYPE http_response_size_bytes histogram
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="1024"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="2048"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="5120"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="10240"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="102400"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="512000"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="1.048576e+06"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="2.62144e+06"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="5.24288e+06"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="1.048576e+07"} 1
    http_response_size_bytes_bucket{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice",le="+Inf"} 1
    http_response_size_bytes_sum{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice"} 0
    http_response_size_bytes_count{code="500",method="GET",url="/internal/didman/v1/did/:did/compoundservice"} 1
    # HELP nuts_dag_transactions_total Number of transactions stored in the DAG
    # TYPE nuts_dag_transactions_total counter
    nuts_dag_transactions_total 203
    # HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
    # TYPE promhttp_metric_handler_requests_in_flight gauge
    promhttp_metric_handler_requests_in_flight 1
    # HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
    # TYPE promhttp_metric_handler_requests_total counter
    promhttp_metric_handler_requests_total{code="200"} 0
    promhttp_metric_handler_requests_total{code="500"} 0
    promhttp_metric_handler_requests_total{code="503"} 0


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