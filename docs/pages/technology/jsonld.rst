.. _jsonld:

JSON-LD
#######

`JSON Linked Data (JSON-LD) <https://json-ld.org/>`_ is a lightweight Linked Data format. It is easy for humans to read and write.
It is based on the already successful JSON format and provides a way to help JSON data interoperate at Web-scale.
JSON-LD is an ideal data format for programming environments, REST Web services, and unstructured databases.

Within Verifiable Credentials, JSON-LD is used to convert it to a normalized document. Normalization is required for proof generation and validation.

Nuts Context V2
***************

```{eval-rst}
.. jsoninclude:: https://raw.githubusercontent.com/nuts-foundation/nuts-node/master/vcr/assets/assets/contexts/nuts-v2.ldjson
    :jsonpointer: /
```

Nuts Context V1
***************

```{eval-rst}
.. jsoninclude:: https://raw.githubusercontent.com/nuts-foundation/nuts-node/master/vcr/assets/assets/contexts/nuts.ldjson
    :jsonpointer: /
```