.. _nuts_network_reprocess:

nuts network reprocess
----------------------

Reprocess all transactions with the give contentType (ex: application/did+json)

**Synopsis**

Reprocess all transactions with the give contentType (ex: application/did+json)

::

  nuts network reprocess [contentType] [flags]

**Options**
::

  -h, --help   help for reprocess

      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")