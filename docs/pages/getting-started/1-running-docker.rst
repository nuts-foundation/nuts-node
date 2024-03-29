.. _running-docker:

Running on Docker
#################

If you already use Docker, the easiest way to get your Nuts Node up and running for development or production is
using Docker. This guide helps you to configure the Nuts node in Docker.
To use the most recent release use ``nutsfoundation/nuts-node:latest``. For production environments it's advised to use a specific version.

First determine the working directory for the Nuts node which will contain configuration and data. These which will be mounted into the Docker container.
Follow the :ref:`configuration <configure-node>` to setup the configuration of your node.

Mounts
******

Using this guide the following resources are mounted:

- Readonly PEM file with TLS certificate and private key. They can be separate but in this example they're contained in 1 file.
- Readonly PEM file with TLS truststore for the particular network you're connecting to.
- Readonly ``nuts.yaml`` configuration file.
- Data directory where data is stored.

Docker ``run``
**************

If you want to run without Docker Compose you can use the following command from the working directory:

.. code-block:: shell

  docker run --name nuts -p 8080:8080 -p 8081:8081 \
    --mount type=bind,source="$(pwd)"/nuts.yaml,target=/opt/nuts/nuts.yaml,readonly \
    --mount type=bind,source="$(pwd)"/data,target=/opt/nuts/data \
    -e NUTS_CONFIGFILE=/opt/nuts/nuts.yaml \
    nutsfoundation/nuts-node:latest

This setup uses the following ``nuts.yaml`` configuration file:

.. code-block:: yaml

  strictmode: false

.. note::

    The command above uses ``pwd`` and ``bash`` functions, which do not work on Windows. If running on Windows replace
    it with the path of the working directory.
    
    If your use case makes use of did:nuts DIDs, you also need to map port ``5555``, which is used for gRPC traffic by the Nuts network.

You can test whether your Nuts Node is running properly by visiting ``http://localhost:8081/status/diagnostics``. It should
display diagnostic information about the state of the node.

Docker Compose
**************

Copy the following YAML file and save it as ``docker-compose.yaml`` in the working directory.

.. code-block:: yaml

  services:
    nuts:
      image: nutsfoundation/nuts-node:latest
      environment:
        NUTS_CONFIGFILE: /opt/nuts/nuts.yaml
      ports:
        - 8080:8080
        - 8081:8081
      volumes:
        - "./nuts.yaml:/opt/nuts/nuts.yaml:ro"
        - "./data:/opt/nuts/data:rw"


Start the service:

.. code-block:: shell

  docker compose up

Development image
*****************

There's also a development image available which includes an HTTPS tunnel.
This is useful for development and testing purposes. In order to use it, you need a Github account.
The development image is available at Docker hub under ``nutsfoundation/nuts-node:dev``.

You can also build the development image yourself by running the following command in the root of the repository:

.. code-block:: shell

  make docker-dev

When starting up the development image, it'll block and requires you to authenticate with Github.
It'll print a URL to visit in your browser and a code to enter. After authenticating, the tunnel will be established and the Nuts Node will start.
To save the tunnel configuration, mount a directory to ``/devtunnel`` inside the container. The last used tunnel is stored in ``/devtunnel/tunnel.id``.
``devtunnel/tunnel.log`` contains the logs of the tunnel including the public accessible URL. This URL is also printed to the console.