#  Nuts Node Documentation

Building the documentation is mostly done on readthedocs based on settings configured on `.readthedocs.yaml` in the project root.

To build the documentation locally, run `make cli-docs` in the parent directory first and then compile the rest in the `_build` directory using:

```shell
docker build -t nuts-node-docs .
docker run --rm -v $PWD:/docs nuts-node-docs
```
