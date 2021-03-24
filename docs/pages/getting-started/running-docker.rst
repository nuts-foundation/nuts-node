.. _running-docker:

Getting Started on Docker
#########################

If you already use Docker, the easiest way to get your Nuts Node up and running for development or production is
using Docker. To use the latest `master` build use `nutsfoundation/nuts-node:master` (for production environments
it's advisable to use a specific version).

First determine the working directory for the Nuts node which will contain configuration and data. These which will be mounted into the Docker container.

Node TLS Certificate
********************

To connect to an existing Nuts network you need a TLS certificate which authenticates your node. For the development network
you can use the `nuts-network-development-ca` to directly issue a certificate for your node. The commands below clone
the required Git repository, generate a private key and issues a certificate, and combines them into a single file:

.. code-block:: shell

  git clone https://github.com/nuts-foundation/nuts-development-network-ca
  cd nuts-development-network-ca && ./issue-cert.sh localhost
  cat localhost.key localhost.pem > certificate-and-key.pem

Move `certificate-and-key.pem` to the working directory.

.. note::

    If you want peers to be able to connect to your node, replace `localhost` with the correct hostname.

Note that the Git repository contains the Certificate Authority certificate (`ca.pem`) which will function as truststore.
Copy this file as `truststore.pem` into the working directory.

YAML Configuration File
***********************

Copy the YAML file below and save it as `nuts.yaml` in the working directory:

.. code-block:: yaml

  datadir: /opt/nuts
  network:
    truststorefile: /opt/nuts/truststore.pem
    certfile: /opt/nuts/certificate-and-key.pem
    certkeyfile: /opt/nuts/certificate-and-key.pem


See :ref:`configuration <nuts-node-config>` for more information on what can be configured.

Mounts
******

Using this guide the following resources are mounted:

- Readonly PEM file with TLS certificate and private key. They can be separate but in this example they're contained in 1 file.
- Readonly PEM file with TLS truststore for the particular network you're connecting to.
- Readonly `nuts.yaml` configuration file.
- Data directory where data is stored.

Docker Compose
**************

Copy the following YAML file and save it as `docker-compose.yaml` in the working directory.

.. code-block:: yaml

  version: "3.7"
  services:
    nuts:
      image: nutsfoundation/nuts-node:master
      environment:
        NUTS_CONFIGFILE: /opt/nuts/nuts.yaml
      ports:
        - 5555:5555
        - 1323:1323
      volumes:
        - "./certificate-and-key.pem:/opt/nuts/certificate-and-key.pem:ro"
        - "./truststore.pem:/opt/nuts/truststore.pem:ro"
        - "./nuts.yaml:/opt/nuts/nuts.yaml:ro"
        - "./data:/opt/nuts/data:rw"


Start the service:

.. code-block:: shell

  docker-compose up

Without Docker Compose
**********************

If you want to run without Docker Compose you can use the following command from the working directory:

.. code-block:: shell

  docker run --name nuts -p 5555:5555 -p 1323:1323 \
    --mount type=bind,source="$(pwd)"/certificate-and-key.pem,target=/opt/nuts/certificate-and-key.pem,readonly \
    --mount type=bind,source="$(pwd)"/truststore.pem,target=/opt/nuts/truststore.pem,readonly \
    --mount type=bind,source="$(pwd)"/nuts.yaml,target=/opt/nuts/nuts.yaml,readonly \
    --mount type=bind,source="$(pwd)"/data,target=/opt/nuts/data \
    -e NUTS_CONFIGFILE=/opt/nuts/nuts.yaml \
    nutsfoundation/nuts-node:master

.. note::

    The command above uses `pwd` and `bash` functions, which do not work on Windows. If running on Windows replace
    it with the path of the working directory.

You can test whether your Nuts Node is running properly by visiting `http://localhost:1323/status/diagnostics`. It should
display diagnostic information about the state of the node.
