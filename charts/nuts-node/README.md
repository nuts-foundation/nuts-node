# Helm Chart for NUTS
This chart allows the ease of running NUTS on a Kubernetes cluster. 
All the NUTS node information is persisted on [Persisted Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/).

## Configure your NUTS node
All the configurable properties can be found at [./values.yaml](./values.yaml).

When configuring the NUTS node for production purposes, please consult [this](https://nuts-node.readthedocs.io/en/latest/pages/production-configuration.html)
NUTS guide.

The configuration contains default Helm properties. In addition to these values,
there are `nuts` config properties. This contains 3 sections:

| Section     | Description                                                                                                                                                                                                        |
|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `nuts.config` | Represents the `nuts.yaml` file. All configurable properties can be found in the main [README](../../README.rst#server-options). The properties are loaded into a `ConfigMap` and mounted as `/opt/nuts/nuts.yaml` inside the Pod(s). |
| `nuts.data`   | Contains configurable properties for the `PersistedVolume` that will be created. This will be used to write all NUTS data to.                                                                                |
| `nuts.ssl`    | Can be used to load the ssl `certfile`, `certkeyfile` and `truststorefile` as a `Secret` and mount them as files at `/opt/nuts/ssl` inside the Pod(s)                                                              |

### Special properties
NUTS allows binding to specific interfaces on the host machines. In the case of Kubernetes, this is already taken care 
of. However, we do need to expose the `http` and `gRPC` ports. This is extracted from the following properties:

| Property                                                                  | Value (default) |
|---------------------------------------------------------------------------|-----------------|
| `http.external.address` (must align with `service.external.internalPort`) | :8080           |
| `http.internal.address` (must align with `service.internal.internalPort`) | :8081           |
| `network.grpcaddr`                                                        | :5555           | 

For the `nuts-node` port, the `service.internalPort` can simply be used. For gRPC, the Helm chart filters out all digits 
after the last `:` character. If not set, defaults will be used.

### Overriding values
#### From Source
The properties can be manually changed in the [./values.yaml](./values.yaml), or they can be overwritten whilst running
`helm install` via the `--set x=y` parameter.

#### From the NUTS Helm Repo
 
The default values can be viewed with the following command: 
```shell
helm show values nuts-repo/nuts-node-chart
```

You can then override any of these settings in a YAML formatted file, and then pass that file during [installation](#from-the-nuts-helm-repo-1).

## Installing NUTS
### From Source

Execute the following command from the root of the chart folder. Replace `<NAME>` with the name you 
wish to give this Helm installation.
```
helm install <NAME> .
```
### From the NUTS Helm Repo

Add the NUTS helm Repo with the following command:
```shell 
helm repo add nuts-repo https://nuts-foundation.github.io/nuts-node/
```
This should list available releases with the following command:
```shell
helm search repo nuts-repo
```

After this, the desired version can be installed with the following command:
```shell
helm repo update              # Make sure we get the latest list of charts
helm install -f values.yaml <NAME> nuts-repo/nuts-node-chart
```

Note that the `values.yaml` in the above command is the result from the [configuration step](#from-the-nuts-helm-repo).

## Uninstalling NUTS
As the `PersistedVolume` can contain crucial data (like the private keys), by default, the uninstall command will not remove it and its 
`PersistedVolumeClaim`. If you're sure it can be deleted, this can be done with the following command:
```shell
kubectl delete pvc nuts-data-pvc
kubectl delete pv nuts-data-pv
```
