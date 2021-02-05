.. _produection-configuration:

Configuring for Production
##########################

Running a Nuts node in a production environment has to other requirements than a development or test environment.
This page will instruct how to configure your node for running in production and what to consider.

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