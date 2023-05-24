# Nuts Node Documentation

Documentation gets compiled with a mixture of tooling into the `_build` directory.

Run `make docs` in the parent/base directory first.

```shell
docker build -t nutsfoundation/nuts-node-docs .
docker run --rm -v $PWD:/docs nutsfoundation/nuts-node-docs
```
