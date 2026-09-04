#  Nuts Node Documentation

Building the documentation is mostly done on readthedocs based on settings configured on `.readthedocs.yaml` in the project root.

To build the documentation locally, run `make cli-docs` in the parent directory first and then compile the rest in the `_build` directory using:

```shell
docker build -t nuts-node-docs .
docker run --rm -v $PWD:/docs nuts-node-docs
```

## API development guidelines

When developing APIs, please follow these guidelines.

### Contract first

The Nuts node APIs are specified in [Open API Specification (OAS)](https://swagger.io/specification/).
The files are located under `/docs/_static/<engine>/<version>.yaml`, where `<engine>` is a specific module like `crypto` or `auth`, and `<version>` defines the version of the API.
We use version `3.0.y` of the OAS.

#### Versioning

We use versioning of the APIs. This is reflected in both the OAS files and the HTTP paths.
Versions must follow the pattern `v` and start at `v1`. These are major versions: any breaking change results in a new major version of the API.
New additions, bug fixes and changes that are backwards compatible may be done in the current version.

#### Code generation

The OAS files are used for code generation. The makefile contains the `gen-api` target which generates the code.
The build target only needs to be extended when a new version or new engine is added.
Generated code is always placed in `/<engine>/api/<version>/generated.go`.

#### Return codes

The error return values are generalized for all API calls. The return values follow [RFC7807](https://tools.ietf.org/html/rfc7807).
The definition is available under `/docs/_static/common/error_response.yaml`. The error definition can be used in an OAS file:

```yaml
paths:
  /some/path:
    get:
      responses:
        default:
          $ref: '../common/error_response.yaml'
```

The error responses will not be listed as responses in the online generated documentation.
To describe error responses, the specific responses need to be added to the API description:

```yaml
paths:
  /some/path:
    post:
      description: |
        Some description on the API

        error returns:
        * 400 - incorrect input
```

### Paths

The API paths are designed so it's clear which APIs are to be blocked for external traffic.

- `/internal/**` These APIs are meant to be behind a firewall and should only be available to the internal infrastructure.
