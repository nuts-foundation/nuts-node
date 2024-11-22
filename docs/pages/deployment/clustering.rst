.. _clustering:

Clustering
##########

Clustering is currently limited to nodes that have the ``did:nuts`` method disabled.
To enable clustering, you must support the following:

- A clustered SQL database (SQLite is not supported)
- A clustered session storage (Redis sentinel is recommended)
- A clustered private key storage (Hashicorp Vault or Azure Keyvault)
- Read only mounts for configuration, policy, discovery and JSON-LD context files.

It's recommended to use a level 4 load balancer to distribute the load across the nodes.
Each node should have a reverse proxy for TLS termination.

Clustering will not work if you use one of the following:

- The did:nuts method
- SQLite
- Disk based private key storage
