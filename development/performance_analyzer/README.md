This directory contains all files needed to build a docker container that includes [node-exporter](https://github.com/prometheus/node_exporter) for performance testing.

## Configuring node-exporter
Many [collectors](https://github.com/prometheus/node_exporter#collectors) are configured by default. 
Changes to the default settings can be made in `node-exporter.conf` (collectors, port, ...).

If a specific setup is needed for a test, just create a new configuration file and mount it to `/etc/conf.d/node-exporter` 

## Building nuts-node:dev container
Containers can be build using the makefile.
```shell
# build nutsfoundation/nuts-node:dev FROM nutsfoundation/nuts-node:master
make

# build nutsfoundation/nuts-node:master locally and then use this to build nutsfoundation/nuts-node:dev
make build-local
```

## Collecting metrics
By default, node-exporter exposes the prometheus metrics at `/metrics` on port `:9100`.
These metrics can be collected by adding a scrape config to the [prometheus](https://prometheus.io/docs/guides/node-exporter/) config
```yaml
scrape_configs:
  - job_name: node
    metrics_path: '/metrics'
    scrape_interval: 5s
    static_configs:
      - targets: 
        - '<address>:1323'  # metrics exposed on nuts-node/metrics
        - '<address>:9100'  # metrics exposed by node-exporter
```

Note: metrics prepended with `go_` from the `node-exporter` and `nuts-node` targets are different. 
Perhaps these relate to the target process (nuts-node / node-exporter) itself??

