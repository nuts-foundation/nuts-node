.. table:: Client Options
    :widths: 20 30 50
    :class: options-table

    ==========      ==============      =====================================================================================================================================================================
    Key             Default             Description                                                                                                                                                          
    ==========      ==============      =====================================================================================================================================================================
    address         localhost:8081      Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended.                                         
    timeout         10s                 Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.
    token                               Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.                                                                          
    token-file                          File from which the authentication token will be read. If not specified it will try to read the token from the '.nuts-client.cfg' file in the user's home dir.       
    verbosity       info                Log level (trace, debug, info, warn, error)                                                                                                                          
    ==========      ==============      =====================================================================================================================================================================
