.. _nuts_vdr_conflicted:

nuts vdr conflicted
-------------------

Print conflicted documents and their metadata

**Synopsis**

Print conflicted documents and their metadata

::

  nuts vdr conflicted [flags]

**Options**
::

      --document   Pass 'true' to only print the document (unless other flags are provided as well).
  -h, --help       help for conflicted
      --metadata   Pass 'true' to only print the metadata (unless other flags are provided as well).

      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")