The certificates and keys in this directory should be valid development network materials. 
These are generated with the following commands:
```shell
git clone https://github.com/nuts-foundation/nuts-development-network-ca.git
cd nuts-development-network-ca
./issue-cert.sh development nuts-node       # the node certificate
./issue-cert.sh development client-allowed  # certificate that should be accepted by the node
./issue-cert.sh development client-blocked  # certificate that should be rejected by the node (must be on to the denylist)
```
The `client-blocked.crt` must also be replaced on the `nuts-foundation/denylist` when regenerating the certificates.  
The truststore should be the development network truststore.