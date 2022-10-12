# Nuts Node Documentation

Documentation gets compiled with a mixture of tooling.

```shell
docker build -t nutsfoundation/nuts-node-docs .
docker run --rm -v $PWD:/docs nutsfoundation/nuts-node-docs sphinx-build -M html . _build
```
