.. _prodruction-configuration:

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

By default all HTTP endpoints get bound on `localhost:1323` which generally isn't usable for production, since there are
endpoints which are required to be accessible by the public. For instance `auth` engine HTTP endpoints required for IRMA
authentication flows. However, having all endpoints open to the public would be very unsafe, so it's advisable to bind
public endpoints to publicly accessible interfaces or ports and have administrative endpoints only accessible from
secure subnets. This is done through the `http` configuration:

.. code-block:: yaml

    http:
      # The following is the default binding which endpoints are bound to,
      # which don't have an alternative bind specified under `alt`. Since it's a default it can be left out or
      # be used to override the default bind address.
      default:
        address: localhost:1323
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
