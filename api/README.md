Several of the OpenAPI files refer to the same 'things' such as VCs, DIDs, DID Documents, etc.
To keep the schemas in sync over all OpenAPI files we have defined these shared schemas in `docs/_static/common/ssi_types.yaml`.

The tests defined here serve to verify that the structs generated from these schemas match the structs we use internally.