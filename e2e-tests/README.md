
# Writing tests
## Automated testing
[Automated testing](https://github.com/nuts-foundation/nuts-node/blob/master/.github/workflows/e2e-tests.yaml) of the nuts-node relies on some find and replace magic for which the following requirements must be met:

- Each test has a `docker-compose.yml` and a `run-test.sh` file. 
- References to Docker image `nutsfoundation/nuts-node:master` in the `docker-compose.yml` file are automatically replaced with the image that is built in the automated test.
- The `run-test.sh` of each test should be added to the respective group's `/<test-group>/run-tests.sh` script.
- All `/<test-group>/run-tests.sh` should be added to `/run-tests.sh`

If the `datadir` needs to be mounted for a test, add `USER=$UID` to the top of the test's `run-test.sh`, and add `user: "$USER:$USER"` to each service in the `docker-compose.yml` that mounts a `datadir`.

# Running tests
## Prerequisites
To tun the tests you need the following tools:

- Docker
- [jq](https://stedolan.github.io/jq/) for JSON operations

## On your machine

Run `./run-tests.sh` in `./e2e-tests`

## Testing version compatibility

By default, the test are performed on the master build: `nutsfoundation/nuts-node:master`.

Sometimes you want to test compatibility between versions. To aid this, every node in this test suite you can specify 2 environment variables to control exact Docker image to use:

- `IMAGE_NODE_A`
- `IMAGE_NODE_B`

When there are multiple in a test, some will use `IMAGE_NODE_A` and the other `IMAGE_NODE_B`.
Since tests are asymmetric (the action is only performed from node A to B), you want to run the tests twice with the image variables swapped, e.g.:

```console
IMAGE_NODE_A=nutsfoundation/nuts-node:v4.3.0 \
IMAGE_NODE_B=nutsfoundation/nuts-node:v5.0.0 \
./run-tests.sh
```

And then run again with the values swapped:
```console
IMAGE_NODE_A=nutsfoundation/nuts-node:v5.0.0 \
IMAGE_NODE_B=nutsfoundation/nuts-node:v4.3.0 \
./run-tests.sh
```

