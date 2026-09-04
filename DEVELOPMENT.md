# Developing nuts-node

## Requirements

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/nuts-foundation/nuts-node)
or higher is required.

## Building

Just use `go build`.

### ES256 Koblitz support

To enable ES256K (Koblitz) support, you need to build with the `jwx_es256k` tag:

```shell
go build -tags jwx_es256k
```

## Running tests

Tests can be run by executing

```shell
go test ./...
```

## Code generation

Code generation is used for generating mocks, OpenAPI client- and servers, and gRPC services.
Make sure that `GOPATH/bin` is available on `PATH` and that the dependencies are installed.

Install `protoc`:

- MacOS: `brew install protobuf`
- Linux: `apt install -y protobuf-compiler`

Install Go tools:

```shell
make install-tools
```

Generating code:

To regenerate all code run the `run-generators` target from the makefile, or use one of the following for a specific group:

| Group           | Command               |
|-----------------|------------------------|
| Mocks           | `make gen-mocks`      |
| OpenApi         | `make gen-api`        |
| Protobuf + gRPC | `make gen-protobuf`   |
| All             | `make run-generators` |

See [docs/README.md](docs/README.md) for API development guidelines (OpenAPI contract-first workflow, versioning, error responses).

### Documentation

The documentation is automatically built on readthedocs based on the config in `.readthedocs.yaml`.
All files to be included can be generated using:

```shell
make cli-docs
```

This regenerates the config-option and CLI reference tables from code, and the root `README.rst` from `README_template.rst`.
Whenever you add, remove, or change a config flag or CLI command, run this and commit the regenerated files —
don't hand-edit `docs/pages/configuration/server_options*.rst` or `docs/pages/operations/cli-reference.rst`.

If needed, you can also build the documentation locally in `/docs/_build` using Docker; see [docs/README.md](docs/README.md).

## Developing with Vault

You can start a development Vault server as follows:

```shell
docker run --cap-add=IPC_LOCK -d -p 8200:8200 \
-e 'VAULT_DEV_ROOT_TOKEN_ID=unsafe' -e 'VAULT_ADDRESS=http://localhost:8200' \
--name=dev-vault \
vault
```

The server will start unsealed, with root token `unsafe`.

Now log in and enable a key-value secret engine named `kv`:

```shell
docker exec -e 'VAULT_ADDR=http://0.0.0.0:8200' dev-vault vault login
```

Enter the root token `unsafe`, then enable the `kv` engine:

```shell
docker exec -e 'VAULT_ADDR=http://0.0.0.0:8200' dev-vault vault secrets enable -path=kv kv
```

Then configure the Nuts node to use the Vault server:

```yaml
crypto:
  storage: vaultkv
  vault:
    address: http://localhost:8200
    token: unsafe
```
