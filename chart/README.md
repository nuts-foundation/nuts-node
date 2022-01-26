# Helm Chart for NUTS
This chart allows the ease of running NUTS on a Kubernetes cluster. 
All the NUTS node information is persisted on [Persisted Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/).

## Installing NUTS

### Configure your NUTS node
All the configurable properties can be found at [./values.yaml](./values.yaml).

When configuring the NUTS node with production purposes, please consult [this](https://nuts-node.readthedocs.io/en/latest/pages/production-configuration.html)
NUTS guide.

The configuration contains default Helm properties. In addition to these values,
there are `nuts` config properties. This contains 3 sections:

| Section     | Description                                                                                                                                                                                                        |
|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `nuts.config` | Represents the `nuts.yaml` file. All configurable properties can be found in the main [README](../README.rst). The properties are loaded into a `ConfigMap` and mounted as `/opt/nuts/nuts.yaml` inside the Pod(s). |
| `nuts.data`   | Contains configurable properties for the `PersistedVolume` that will be created. This will be used to write all NUTS data to.                                                                                |
| `nuts.ssl`    | Can be used to load the ssl `certfile`, `certkeyfile` and `truststorefile` as a `Secret` and mount them as files at `/opt/nuts/ssl` inside the Pod(s)                                                              |

#### Overriding values
The properties can be manually changed in the [./values.yaml](./values.yaml), or they can be overwritten whilst running
`helm install` via the `--set x=y` parameter. For example:
```
helm install nuts --set nuts.config.network.enabletls=false ./chart
```

### Execute the installation
#TODO - add repo push / pull information