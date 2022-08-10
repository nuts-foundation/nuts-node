.. _tls-configuration:

TLS Configuration
#################

The Nuts nodes uses 2 kinds of connections: HTTP and gRPC. gRPC connections and some HTTP endpoints require TLS to be set up,
either for being able to connect to other nodes and/or secure access to the local Nuts node.
You can review these requirements in the :ref:`Interfaces/Endpoints section of the deployment documentation <nuts-node-recommended-deployment>`.

Generally speaking:

* Connections between Nuts nodes (gRPC and HTTP) are secured using mutual TLS (both client and server present a X.509 certificate).
* Connections from the "outside world" (HTTP), e.g. mobile devices, are secured using TLS with only a server certificate.

Your TLS configuration depends mostly on where you `terminate the TLS connection <https://en.wikipedia.org/wiki/TLS_termination_proxy>`_.
This page describes the different layouts for TLS and how to configure them.

All layouts your node's certificate must be issued by a Certificate Authority which is trusted by the other nodes in the network.
Each layout requires ``tls.certfile``, ``tls.certkeyfile`` and ``tls.truststorefile`` to be configured.

.. note::

    You can find working setups in the `end-2-end test suite <https://github.com/nuts-foundation/nuts-go-e2e-test>`_.

End-to-end TLS (no offloading)
******************************

Having no TLS offloading means the secure connection starts at the remote system and ends at the Nuts node.
No systems in between can alter or inspect the TLS connection.

.. raw:: html
    :file: ../../_static/images/diagrams/network infrastructure layouts-Direct-WAN-Connection.svg

For this setup you need to configure TLS and set up the HTTP interfaces so the endpoints are properly secured.
The example below shows how to:

* configure TLS for HTTP and gRPC connections,
* enable TLS (with required client certificate) for node-to-node (``/n2n``) HTTPS connections on port ``8443``,
* enable TLS (server certificate only) for ``/public`` HTTPS connections on port ``443``.

Your Nuts node configuration could look like this:

.. code-block:: yaml

    tls:
      certfile: my-certificate.pem
      certkeyfile: my-certificate.pem
      truststorefile: truststore.pem
    http:
      default:
        address: :1323
      alt:
        public:
          address: :443
          tls: server-cert
        n2n:
          address: :8443
          tls: server-and-client-cert

.. note::

    In the example above ``/internal`` endpoints bind to the default HTTP interface, which does not apply any access control.
    To secure your node you must restrict access this endpoint, e.g. by not exposing it to the outside world.
    It's generally preferable to use an external load balancer (see "TLS Pass-through") or firewall to decrease the risk of misconfiguration of the node.
    You can bind ``/internal`` to its own HTTP interface to further decrease the risk.

TLS Pass-through
^^^^^^^^^^^^^^^^

When using a (level 4) load balancer that does not inspect or alter requests, TLS is still terminated on the Nuts node.

.. raw:: html
    :file: ../../_static/images/diagrams/network infrastructure layouts-TLS-Pass-through.svg

This set up does not need additional configuration.

Configuration for `HAProxy <https://www.haproxy.com/>`_ could look like this (given the TLS configuration in the previous section):

.. code-block::

    listen grpc
        bind *:5555
        mode tcp
        use_backend nuts_node_grpc

    backend nuts_node_grpc
        mode tcp
        server node1 nodeA-backend:5555 check

    listen public_https
        bind *:443
        mode tcp
        use_backend nuts_node_public_https

    backend nuts_node_public_https
        mode tcp
        server node1 nodeA-backend:443 check

    listen n2n_https
        bind *:8443
        mode tcp
        use_backend nuts_node_n2n_https

    backend nuts_node_n2n_https
        mode tcp
        server node1 nodeA-backend:8443 check


Refer to the HAProxy documentation for more information.

TLS Offloading
**************

In many setups TLS is terminated on a reverse proxy in front of the backend services over plain HTTP or HTTP/2 (for gRPC connections).

.. raw:: html
    :file: ../../_static/images/diagrams/network infrastructure layouts-TLS-Offloading.svg

To configure this setup your proxy needs to support HTTP/2 for gRPC traffic.
For gRPC traffic your proxy must add the TLS client certificate as request header.
The certificate can either be in PEM (Apache HTTPD/NGINX) or DER (HAProxy) format and URL encoded.

In addition to the general TLS configuration, you need to configure the following options:

* ``tls.offload`` needs to be set to ``incoming``
* ``tls.certheader`` needs to be set to the name of the header in which your proxy sets the certificate (e.g. ``X-SSl-CERT``).
  The certificate must in be PEM or base64 encoded DER format.
* Disable/remove TLS configuration for HTTP interfaces.
* Bind the ``/n2n`` and ``/public`` endpoints to specific different HTTP interfaces to avoid accidentally exposing internal HTTP endpoints.

Your Nuts node configuration could look like this:

.. code-block:: yaml

    tls:
      certfile: my-certificate.pem
      certkeyfile: my-certificate.pem
      truststorefile: truststore.pem
      offload: incoming
      certheader: X-SSL-CERT
    http:
      default:
        address: :1323
      alt:
        public:
          address: :80
        n2n:
          address: :8080

The certificate and truststore will still need to be available to the Nuts node for making outbound connections.

For `NGINX <https://www.nginx.com/>`_ the proxy configuration could look as follows:

.. code-block::

    upstream nuts-node-http-public {
      server nuts-node:80;
    }
    upstream nuts-node-http-n2n {
      server nuts-node:8080;
    }
    upstream nuts-node-grpc {
      server nuts-node:5555;
    }

    server {
      server_name nuts-grpc;
      listen                    5555 ssl http2;
      ssl_certificate           /etc/nginx/ssl/server.pem;
      ssl_certificate_key       /etc/nginx/ssl/key.pem;
      ssl_client_certificate    /etc/nginx/ssl/truststore.pem;
      ssl_verify_client         on;
      ssl_verify_depth          1;

      location / {
        grpc_pass grpc://nuts-node-grpc;
        grpc_set_header X-SSL-CERT $ssl_client_escaped_cert;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; // for correct IP logging
      }
    }

    server {
      server_name nuts-n2n;
      listen                    443 ssl http;
      ssl_certificate           /etc/nginx/ssl/server.pem;
      ssl_certificate_key       /etc/nginx/ssl/key.pem;
      ssl_client_certificate    /etc/nginx/ssl/truststore.pem;
      ssl_verify_client         on;
      ssl_verify_depth          1;

      location / {
        proxy_pass http://nuts-node-http-n2n
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; // for correct IP logging
      }
    }

    server {
      server_name nuts-public;
      listen                    443 ssl http;
      ssl_certificate           /etc/nginx/ssl/server.pem;
      ssl_certificate_key       /etc/nginx/ssl/key.pem;

      location / {
        proxy_pass http://nuts-node-http-public
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; // for correct IP logging
      }
    }

For `HAProxy <https://www.haproxy.com/>`_ the proxy configuration could look as follows:

.. code-block::

    frontend grpc_service
        mode http
        bind :5555 proto h2 ssl crt /certificate.pem ca-file /truststore.pem verify required
        default_backend grpc_servers

    backend grpc_servers
        mode http
        http-request set-header X-SSL-CERT %{+Q}[ssl_c_der,base64]
        server node1 nuts_node:5555 check proto h2

No TLS
******

You can disable TLS by setting ``network.enabletls`` to ``false``, but this feature is **only** meant for development/demo purposes.
It should never be used in a production environment. If you disable TLS, you can only connect to nodes that have disabled TLS as well.
