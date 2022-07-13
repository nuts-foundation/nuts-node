.. _nuts_vcr_list-trusted:

nuts vcr list-trusted
---------------------

List trusted issuers for given credential type

**Synopsis**

List trusted issuers for given credential type

::

  nuts vcr list-trusted [type] [flags]

**Options**
::

  -h, --help   help for list-trusted

      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")