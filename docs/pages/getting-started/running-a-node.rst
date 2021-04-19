.. _running-native:

Getting Started with native binary
##################################

The Nuts executable this project provides can be used to both run a Nuts server (a.k.a. node) and administer a running
node remotely. This chapter explains how to run a server using the native binary.

Building
********

Since no precompiled binaries exist (yet), you'll have to build the binary for your platform.

First check out the project using:

.. code-block:: shell

    git clone https://github.com/nuts-foundation/nuts-node
    cd nuts-node

Then create the executable using the `make` command:

.. code-block:: shell

    make build

Or if make is not available:

.. code-block:: shell

    go build -ldflags="-w -s -X 'github.com/nuts-foundation/nuts-node/core.GitCommit=GIT_COMMIT' -X 'github.com/nuts-foundation/nuts-node/core.GitBranch=GIT_BRANCH' -X 'github.com/nuts-foundation/nuts-node/core.GitVersion=GIT_VERSION'" -o /path/to/nuts

Make sure `GIT_COMMIT`, `GIT_BRANCH` and `GIT_VERSION` are set as environment variables.
These variables help identifying an administrator and other nodes what version your node is using.
If this isn't important then replace `GIT_COMMIT` with `0`, `GIT_BRANCH` with `master` and `GIT_VERSION` with `undefined`.

Starting
********

Start the server using the `server` command:

.. code-block:: shell

    nuts server

Now continue with the :ref:`configuration <configure-node>`.


