.. _nuts_status:

nuts status
-----------

Shows the status of the Nuts Node.

**Synopsis**

Shows the status of the Nuts Node.

::

  nuts status [flags]

**Options**
::

      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
  -h, --help               help for status
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")