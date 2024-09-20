.. _nuts-node-logging:

Logging
#######

The Nuts Node writes its logs to standard out.
By default it logs in text format, but it can be configured to log in JSON format.
This is especially useful when using log collection tools (e.g. `fluentd <https://www.fluentd.org/>`_) and recommended for production environments.

To enable JSON logging, set the ``loggerformat`` to ``json`` in the configuration file.
Example logs message in JSON format:

.. code-block:: json

   {
     "did": "did:nuts:AmEcvjhiGxxkiByWyrN7VTapk9cXaUU8UozwWqJC7VKY",
     "level": "info",
     "module": "VDR",
     "msg": "DID document registered",
     "time": "2023-01-14T07:34:16+01:00",
     "txRef": "052a8ef99f1f641ea47cc15ca5a5c7b68028ebbf886b07898937d4303e3ea9cb"
   }

The following fields are always available:

- ``module``: the module that logged the message, e.g. ``VDR`` or `Auth``
- ``level``: the level of the log message, e.g. ``info`` or ``error``
- ``time``: the timestamp of the log message, e.g. ``2023-01-14T07:34:16+01:00``
- ``msg``: the actual log message

Operations that manipulate or use private keys directly will generate a log with ``level`` set to ``audit``.