.. _did-administration-cookbook:

DID Document Administration Cookbook
####################################

This chapter contains useful snippets for manipulating your DID Documents using `jq` and `bash`:

Register Nuts Network Endpoint
******************************

To publish a Nuts Network endpoint to let other nodes discover your node, register a service for it
(replace `<DID>` which the relevant DID and `<ENDPOINT>` with your node's gRPC endpoint):

    DID=<DID>
    ENDPOINT=<ENDPOINT>
    ENDPOINT_ID=$(echo -n $(uuidgen))
    DOC=$(nuts vdr resolve ${DID} --document)
    echo $DOC | jq ". |= . + {service: [{id:\"${DID}#${ENDPOINT_ID}\",type:\"nuts-network-grpc\",serviceEndpoint:\"${ENDPOINT}\"}]}"
