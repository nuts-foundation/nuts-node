.. _running-docker:

Running on Docker
#################

This guide helps you to configure the Nuts node in Docker.
To use the most recent release use ``nutsfoundation/nuts-node:latest``. For production environments it's advised to use a specific version.

Examples
********

Docker ``run``
^^^^^^^^^^^^^^

If you want to run without Docker Compose you can use the following command from the working directory:

.. code-block:: shell

  docker run --name nuts -p 8080:8080 -p 8081:8081 \
    -e NUTS_STRICTMODE=false -e NUTS_HTTP_INTERNAL_ADDRESS=":8081" -e URL="http://nuts" \
    nutsfoundation/nuts-node:latest


Docker Compose
^^^^^^^^^^^^^^

Copy the following YAML file and save it as ``docker-compose.yaml`` in the working directory.

.. code-block:: yaml

  services:
    nuts:
      image: nutsfoundation/nuts-node:latest
      environment:
        NUTS_STRICTMODE: false
        NUTS_URL: http://nuts
        NUTS_HTTP_INTERNAL_ADDRESS: :8081
      ports:
        - 8080:8080
        - 8081:8081

Start the service:

.. code-block:: shell

  docker compose up

.. note::

    If your use case makes use of ``did:nuts`` DIDs, you also need to export port ``5555``, which is used for gRPC traffic by the Nuts network,
    and add a volume mount for data on ``/nuts/data`` (see below).

You can test whether your Nuts Node is running properly by visiting ``http://localhost:8081/status/diagnostics``. It should
display diagnostic information about the state of the node.

User
****

The default user in the container is ``18081`` that is only part of group ``18081``.
This is a regular user without root privileges to provide an additional level of security.
If ``datadir`` config value points to a mounted directory, see the section below how to manage privileges needed by the nuts-node.

Volume mounts
*************

The default working directory within the container is ``/nuts`` that provides defaults for the various configurable data and config paths used:

* **/nuts/config/**: Contains all configuration files.
    Any file changes will take effect *after* a node restart. It is recommended to set read-only privileges (default) to this directory and its contents for additional security.
    (``chmod -R o+r </path/to/host/config-dir>`` assuming the directory on the host is *not* owned by user and/or group ``18081``)

* **/nuts/data/**: Storage directory for data managed by the nuts-node.
    The container user (``18081``) has insufficient privileges by default to write to mounted directories.
    The required permissions can be granted by making the container user the owner of the ``data`` directory on the host. (``chown -R 18081:18081 </path/to/host/data-dir>``)

.. note::

    - Nodes running the :ref:`recommended deployment <nuts-node-recommended-deployment>` (external storage configured for ``crypto.storage`` and ``storage.sql.connection``) that do not use did:nuts / gRPC network don't need to mount a ``data`` dir.

    - *"User 18081 already exists on my host."* See `docker security <https://docs.docker.com/engine/security/userns-remap/>`_ (or relevant container orchestration platform) documentation how to restrict privileges to a user namespace / create a user mapping between host and container.

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