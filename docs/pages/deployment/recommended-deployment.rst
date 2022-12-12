.. _nuts-node-recommended-deployment:

Recommended Deployment
######################

This document aims to describe the systems and their components involved in deploying a Nuts node in a production environment.
The target audience are engineers that want to deploy a Nuts Node in their environment for a Service Provider (SP).

It does not detail services and interfaces specified by Bolts: those should be documented by the particular Bolts and should be regarded as extensions to the deployment described here.

The container diagram documents the recommended way of deploying a Nuts node using the features supported by the Nuts node's version.

The diagrams are in `C4 model <https://c4model.com/>`_ notation.

System Landscape
****************

The diagram below depicts the users and systems that interact with the Nuts node of the local SP.

.. image:: ../../_static/images/diagrams/deployment-diagram-System-Landscape-Diagram.svg

Containers
**********

This section details the system with involved containers (which can be native or containerized processes, physical or remote database servers or even networked filesystems).
It lists the interfaces of the Nuts node, who uses them and how they should be secured.

.. image:: ../../_static/images/diagrams/deployment-diagram-Container-Diagram.svg

.. note::

    There are features that might change the recommended deployment, e.g.:

    * Clustering support

Nuts Node
^^^^^^^^^

Server that implements the Nuts specification that connects to the Nuts network. It will usually run as Docker container or Kubernetes pod.

Interfaces/Endpoints
--------------------

* **HTTP /internal**: for managing everything related to DIDs, VCs and the Nuts Node itself. Very sensitive endpoints with no additional built-in security, so care should be taken that no unauthorized parties can access it.
  Since it binds to the shared HTTP interface by default (port ``1323``),
  it is recommended to :ref:`bind it to an alternative interface <production-configuration>` to securer routing.

  *Users*: operators, SPs administrative and EHR applications.

  *Security*: restrict access through network separation and platform authentication.

* **HTTP /public**: for accessing public services, e.g. IRMA authentication.

  *Users*: IRMA app.

  *Security*: HTTPS with **publicly trusted** server certificate (on proxy). Monitor traffic to detect attacks.

* **HTTP /n2n**: for providing Nuts services to other nodes (e.g. creating access tokens).
  The local node also calls other nodes on their `/n2n` endpoint, these outgoing calls are subject to the same security requirements.

  *Users*: Nuts nodes of other SPs.

  *Security*: HTTPS with server- and client certificates (mTLS) **according to network trust anchors** (on proxy). Monitor traffic to detect attacks.

* **gRPC**: for communicating with other Nuts nodes according to the network protocol. Uses HTTP/2 as transport, both outbound and inbound.

  *Users*: Nuts nodes of other SPs.

  *Security*: HTTPS with server- and client certificates (mTLS) **according to network trust anchors** (on proxy). This is provided by the Nuts node.

* **HTTP /status**: for inspecting the health of the server, returns ``OK`` if healthy.

  *Users*: monitoring tooling.

  *Security*: Not strictly required, but advised to restrict access.

* **HTTP /status/diagnostics**: for inspecting diagnostic information of the server.

  *Users*: monitoring tooling, system administrators.

  *Security*: Not strictly required, but advised to restrict access.

* **HTTP /metrics**: for scraping metrics in Prometheus format.

  *Users*: monitoring/metrics tooling.

  *Security*: Not strictly required, but advised to restrict access.

* **stdout**: the server logs to standard out, which can be configured to output in JSON format for integration with existing log tooling.

Subdomains
----------

There are several endpoints that need to be accessed by external systems.
You typically configure 2 subdomains for these, given `example.com` and the acceptance environment:

* `nuts-acc.example.com` for traffic between nodes:

   * HTTP traffic to ``/n2n``

   * gRPC traffic, which will have to be bound on a separate port, e.g. ``5555`` (default).

* ``nuts-public-acc.example.com`` for HTTP traffic to ``/public``

These exact subdomain names are by no means required and can be adjusted to your organization's requirements.

Reverse Proxy
^^^^^^^^^^^^^

Process that protects and routes HTTP and gRPC access (specified above) to the Nuts Node. Typically a standalone HTTP proxy (e.g. NGINX or HAProxy) that resides in a DMZ and/or an ingress service on a cloud platform.
It will act as TLS terminator, with only a server certificate or requiring a client certificate as well (depending on the endpoint).

When terminating TLS on this proxy, make sure to properly verify client certificates for gRPC traffic and HTTP calls to ``/n2n``.
HTTP calls to ``/public`` require a publicly trusted certificate, because mobile devices will query it (the IRMA app).

The Nuts Node looks for a header called ``X-Forwarded-For`` to determine the client IP when logging HTTP and gRPC calls.
Refer to the documentation of your proxy on how to set this header.

Nuts Node Client
^^^^^^^^^^^^^^^^

CLI application used by system administrators to manage the Nuts Node and the SPs presence on the network, which calls the REST API of the Nuts Node.
It is included in the Nuts Node server, so it can be executed in the Docker container (using ``docker exec``) or standalone process.

Database
^^^^^^^^

BBolt database where the Nuts Node stores its data. The database is on disk (by default in ``/opt/nuts/data``) so make sure the data is retained, especially in a cloud environment.
It is recommended to backup the database using the provided backup feature (see config options of the storage engine).

Private Key Storage
^^^^^^^^^^^^^^^^^^^

Creating DID documents causes private keys to be generated, which need to be safely stored so the Nuts node can access them.
It is recommended to store them in `Vault <https://www.vaultproject.io/>`_.
Refer to the config options of the crypto engine and `Vault documentation <https://www.vaultproject.io/docs>`_ for configuring it.

Production Checklist
********************

Below is a list of items that should be addressed when running a node in production:

* TLS
  * Use a proxy in front of the node which terminates TLS
  * Require client certificate on HTTP ``/n2n`` and gRPC endpoints.
  * Make sure only correct CA certificates are in truststore (depends on network)
* Key Management
  * Have a scheduled key rotation procedure
* Backup Management
  * Make sure data is backed up
  * Have a tested backup/restore procedure
* Configuration
  * Make sure ``strictmode`` is enabled
* Security
  * Only allow public access to ``/public``, ``/n2n`` and gRPC endpoints (but the latter 2 still require a client certificate).
  * Make sure ``/internal`` is properly protected
* Availability
  * Consider (D)DoS detection and protection for ``/public``, ``/n2n`` and gRPC endpoints