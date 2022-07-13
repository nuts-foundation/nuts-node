.. _nuts_vcr_trust:

nuts vcr trust
--------------

Trust VCs of a certain credential type when published by the given issuer.

**Synopsis**

Trust VCs of a certain credential type when published by the given issuer.

::

  nuts vcr trust [type] [issuer DID] [flags]

**Options**
::

  -h, --help   help for trust

      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")