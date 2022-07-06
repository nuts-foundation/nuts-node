.. _production-configuration:

Configuring for Production
##########################

Running a Nuts node in a production environment has additional requirements regarding security and data integrity
compared to development or test environments. This page instructs how to :ref:`configure <nuts-node-config>`
your node for running in a production environment and what to consider.

Persistence
***********

All data the node produces is stored on disk in the configured data directory (`datadir`). It is recommended to backup
everything in that directory.

The private keys are stored in a storage backend. Currently 2 options are available.

Vault
^^^^^

This storage backend is the recommended way of storing secrets. It uses the `Vault KV version 1 store <https://www.vaultproject.io/docs/secrets/kv/kv-v1>`_.
The prefix defaults to `kv` and can be configured using the `crypto.vault.pathprefix` option.
There needs to be a KV Secrets Engine (v1) enabled under this prefix path.

All private keys are stored under the path `<prefix>/nuts-private-keys/*`.
Each key is stored under the kid, resulting in a full key path like `kv/nuts-private-keys/did:nuts:123#abc`.
A Vault token must be provided by either configuring it using the config `crypto.vault.token` or setting the VAULT_TOKEN environment variable.
The token must have a vault policy which enables READ and WRITES rights on the path. In addition it needs to READ the token information "auth/token/lookup-self" which should be part of the default policy.

Filesystem
^^^^^^^^^^

This is the default backend but not recommended for production. It stores keys unencrypted on disk. Make sure to include
the directory in your backups and keep these on a safe place.
If you want to use filesystem in strict-mode, you have to set it explicitly, otherwise the node fails during startup.

Migrating from Filesystem storage to Vault
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To migrate from filesystem based storage to Vault you can upload the keys to Vault under `kv/nuts-private-keys`.

Alternatively you can use the `fs2vault` crypto command, which takes the directory containing the private keys as argument (it assumes the container is called `nuts-node`):

    docker exec nuts-node nuts crypto fs2vault /opt/nuts/data/crypto

In any case, make sure the key-value secret engine exists before trying to migrate (default engine name is `kv`).

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
          # The following enables cross-domain requests (CORS) from irma.vendor.nl
          cors:
            origin:
              - irma.vendor.nl
        # The following binds all endpoints starting with `/status` to all interfaces on `:80`
        status:
          address: :80

Cross Origin Resource Sharing (CORS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In some deployments CORS can be required for the public IRMA authentication endpoints when the user-facing
authentication page is hosted on a (sub)domain that differs from Nuts Node's IRMA backend. CORS can be enabled on a
specific HTTP interface by specifying the domains allowed to make CORS requests as `cors.origin` (see the example above).
Although you can enable CORS on the default endpoint it's not advised to do so in a production environment,
because CORS itself opens up new attack vectors on node administrators.

Diagnostics
***********

To aid problem diagnosis every node in a network should share some information about itself; the type and version of software it's running,
which peers it is connected to and how long it's been up. This helps others diagnosing issues when others experience communication problems with your, and other nodes.
Although discouraged, this can be disabled by specifying `0` for `network.advertdiagnosticsinterval`.

Nuts Network SSL/TLS Deployment Layouts
***************************************

This section describes which deployment layouts are supported regarding SSL/TLS. In all layouts there should be
X.509 server and client certificates issued by a Certificate Authority trusted by the network, if the node operator wants
other Nuts nodes to be able to connect to the node and vice versa.

Direct WAN Connection
---------------------

This is the simplest layout where the Nuts node is directly accessible from the internet:

.. raw:: html
    :file: ../../_static/images/network_layouts_directwan.svg

This layout has the following requirements:

* X.509 server certificate and private key must be configured on the Nuts node.
* SSL/TLS terminator must use the trust anchors as specified by the network as root CA trust bundle.

SSL/TLS Offloading
------------------

In this layout incoming TLS traffic is decrypted on a SSL/TLS terminator and then being forwarded to the Nuts node.
This is layout is typically used to provide layer 7 load balancing and/or securing traffic "at the gates":

.. raw:: html
    :file: ../../_static/images/network_layouts_tlsoffloading.svg

This layout has the following requirements:

* X.509 server certificate and private key must be present on the SSL/TLS terminator.
* X.509 client certificate must be configured on the Nuts node.
* SSL/TLS terminator must use the trust anchors as specified by the network as root CA trust bundle.

SSL/TLS Pass-through
--------------------

In this layout incoming TLS traffic is forwarded to the Nuts node without being decrypted:

.. raw:: html
    :file: ../../_static/images/network_layouts_tlspassthrough.svg

Requirements are the same as for the Direct WAN Connection layout.
