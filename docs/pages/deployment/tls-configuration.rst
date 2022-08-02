.. _tls-configuration:

TLS Configuration
#################

Connections between Nuts nodes are secured using mutual TLS (both client and server present a X.509 certificate).
This applies to both gRPC and HTTP connections. Your TLS configuration depends mostly on where you terminate the TLS connection.
This page describes the different layouts for TLS and how to configure them for gRPC.

.. note::

    HTTP connections between nodes (all calls to ``/n2n``) must be secured using TLS which is not handled by the Nuts node.
    You need to have a reverse proxy in front of the Nuts node for terminating the (node-to-node) HTTPS traffic and forwarding it to the Nuts node.
    Refer to :ref:`Interfaces/Endpoints <nuts-node-recommended-deployment>` for the requirements on this HTTP endpoint (and others).

In all layouts your node's certificate must issued by a Certificate Authority, trusted by the other nodes in the network.
Each layout requires ``network.certfile``, ``network.certkeyfile`` and ``network.truststorefile`` to be configured.

You can also find working setups in the `end-2-end test suite <https://github.com/nuts-foundation/nuts-go-e2e-test>`_.

No TLS Offloading
*****************

By default, the TLS connection is terminated on the Nuts node.
This means there is no system between the remote and local Nuts nodes that accepts TLS connections and forwards them as plain HTTP.

.. raw:: html
    :file: ../../_static/images/network_layouts_directwan.svg

No additional configuration is required.

TLS Pass-through
^^^^^^^^^^^^^^^^

When using a (level 4) load balancer that does not inspect or alter requests, TLS is still terminated on the Nuts node.

.. raw:: html
    :file: ../../_static/images/network_layouts_tlspassthrough.svg

This set up does not need additional configuration.

Configuration for `HAProxy <https://www.haproxy.com/>`_ could look like this:

.. code-block::

    listen grpc
        bind *:5555
        mode tcp

        use_backend nuts_node_grpc

    backend nuts_node_grpc
        mode tcp

        server node1 nodeA-backend:5555 check


Refer to the HAProxy documentation for more information.

TLS Offloading
**************

In many setups TLS is terminated on a reverse proxy in front of the backend services over plain HTTP (HTTP/2 in our case).

.. raw:: html
    :file: ../../_static/images/network_layouts_tlsoffloading.svg

To configure this setup your proxy needs to support HTTP/2 or gRPC traffic.
Your proxy must add the TLS client certificate as request header. The certificate must be in PEM format and URL encoded.

In addition to the general TLS configuration, you need to configure the following options:

* ``network.tls.offload`` needs to be set to ``incoming``
* ``network.tls.certheader`` needs to be set to the name of the header in which your proxy sets the certificate (e.g. ``X-SSl-CERT``).

For `NGINX <https://www.nginx.com/>`_ the proxy configuration could look as follows:

.. code-block::

    upstream nuts-node {
      server nuts-node:5555;
    }

    server {
      server_name nuts;
      listen                    443 ssl http2;
      ssl_certificate           /etc/nginx/ssl/server.pem;
      ssl_certificate_key       /etc/nginx/ssl/key.pem;
      ssl_client_certificate    /etc/nginx/ssl/truststore.pem;
      ssl_verify_client         on;
      ssl_verify_depth          1;

      location / {
        grpc_pass grpc://nuts-node;
        grpc_set_header X-SSL-CERT $ssl_client_escaped_cert;
      }
    }

The certificate and truststore will still need to be available to the Nuts node for making outbound connections.

No TLS
******

You can disable TLS by setting ``network.enabletls`` to ``false``, but this feature is **only** meant for development/demo purposes.
It should never be used in a production environment. If you disable TLS, you can only connect to nodes that have disabled TLS as well.
