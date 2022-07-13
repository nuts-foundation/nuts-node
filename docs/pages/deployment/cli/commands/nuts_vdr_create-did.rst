.. _nuts_vdr_create-did:

nuts vdr create-did
-------------------

Registers a new DID

**Synopsis**

Registers a new DID

::

  nuts vdr create-did [flags]

**Options**
::

      --assertionMethod        Pass 'false' to disable assertionMethod capabilities. (default true)
      --authentication         Pass 'true' to enable authentication capabilities.
      --capabilityDelegation   Pass 'true' to enable capabilityDelegation capabilities.
      --capabilityInvocation   Pass 'false' to disable capabilityInvocation capabilities. (default true)
      --controllers strings    Comma-separated list of DIDs that can control the generated DID Document.
  -h, --help                   help for create-did
      --keyAgreement           Pass 'true' to enable keyAgreement capabilities.
      --selfControl            Pass 'false' to disable DID Document control. (default true)

      --address string     Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended. (default "localhost:1323")
      --timeout duration   Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax. (default 10s)
      --verbosity string   Log level (trace, debug, info, warn, error) (default "info")