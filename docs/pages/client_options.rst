.. table:: Client Options
    :widths: 20 30 50
    :class: options-table

    =========      ==============      =====================================================================================================================================================================
    Key            Default             Description                                                                                                                                                          
    =========      ==============      =====================================================================================================================================================================
    address        localhost:1323      Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended.                                  
    timeout        10s                 Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.
    verbosity      info                Log level (trace, debug, info, warn, error)                                                                                                                          
    =========      ==============      =====================================================================================================================================================================
