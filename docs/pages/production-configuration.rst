.. _production-configuration:

Configuring for Production
##########################

Running a Nuts node in a production environment has additional requirements regarding security and data integrity
compared to development or test environments. This page instructs how to :ref:`configure <nuts-node-config>`
your node for running in a production environment and what to consider.

Persistence
***********

All data the node produces is stored on disk in the configured data directory (`datadir`). It is recommended to backup
everything in that directory. However, there are certain directories that absolutely should be part of the backup:

* `crypto`, because it contains your node's private keys

Strict mode
***********

By default the node runs in a mode which allows the operator run configure the node in such a way that it is less secure.
For production it is recommended to enable `strictmode` which blocks some of the unsafe configuration options
(e.g. using the IRMA demo scheme).

HTTP Interface Binding
**********************

By default all HTTP endpoints get bound on `:1323` which generally isn't usable for production, since some endpoints
are required to be accessible by the public and others only meant for administrator or your own XIS. You can determine
the intended public by looking at the first part of the URL.

* Endpoints that start with `/public` should be accessible by the general public,
* `/internal` is meant for XIS application integration and administrators.

It's advisable to make sure internal endpoints aren't reachable from public networks. The HTTP configuration facilitates
this by allowing you to bind sets of endpoints to a different HTTP port. This is done through the `http` configuration:

.. code-block:: yaml

    http:
      # The following is the default binding which endpoints are bound to,
      # which don't have an alternative bind specified under `alt`. Since it's a default it can be left out or
      # be used to override the default bind address.
      default:
        address: :1323
      alt:
        # The following binds all endpoints starting with `/internal` to `internal.lan:1111`
        internal:
          address: internal.lan:1111
        # The following binds all endpoints starting with `/public` to `nuts.vendor.nl:443`
        public:
          address: nuts.vendor.nl:443
        # The following binds all endpoints starting with `/status` to all interfaces on `:80`
        status:
          address: :80

Cross Origin Resource Sharing (CORS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In some deployments CORS can be required for the public IRMA authentication endpoints when the user-facing
authentication page is hosted on a (sub)domain that differs from Nuts Node's IRMA backend. CORS can be enabled on a
specific HTTP interface by specifying `cors: true`. Although you can enable CORS on the default endpoint it's not advised
to do so in a production environment, because CORS itself opens up new attack vectors on node administrators and more so
because when CORS is enabled, it allows requests from all origins using all HTTP methods.

Nuts Network SSL/TLS Deployment Layouts
***************************************

This section describes which deployment layouts are supported regarding SSL/TLS. In all layouts there should be
X.509 server and client certificates issued by a Certificate Authority trusted by the network, if the node operator wants
other Nuts nodes to be able to connect to the node and vice versa.

Direct WAN Connection
---------------------

This is the simplest layout where the Nuts node is directly accessible from the internet:

.. raw:: html
    :file: ../_static/images/network_layouts_directwan.svg

This layout has the following requirements:

* X.509 server certificate and private key must be configured on the Nuts node.
* SSL/TLS terminator must use the trust anchors as specified by the network as root CA trust bundle.

SSL/TLS Offloading
------------------

In this layout incoming TLS traffic is decrypted on a SSL/TLS terminator and then being forwarded to the Nuts node.
This is layout is typically used to provide layer 7 load balancing and/or securing traffic "at the gates":

.. raw:: html
    :file: ../_static/images/network_layouts_tlsoffloading.svg

This layout has the following requirements:

* X.509 server certificate and private key must be present on the SSL/TLS terminator.
* X.509 client certificate must be configured on the Nuts node.
* SSL/TLS terminator must use the trust anchors as specified by the network as root CA trust bundle.

SSL/TLS Pass-through
--------------------

In this layout incoming TLS traffic is forwarded to the Nuts node without being decrypted:

.. raw:: html
    :file: ../_static/images/network_layouts_tlspassthrough.svg

Requirements are the same as for the Direct WAN Connection layout.