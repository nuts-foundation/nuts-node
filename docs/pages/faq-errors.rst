.. _faq-errors:

Frequently Asked Errors
#######################

This section lists commonly seen errors, what they mean and what to do about it.

Error: `connection closed before server preface received`
*********************************************************

When connecting to a remote node, the following error can occur:

    Couldn't connect to peer, reconnecting in XYZ seconds (peer=some.domain.nl:5555,err=unable to connect: context deadline exceeded: connection closed before server preface received)

This indicates the server is using TLS, but the local node is trying to connect without TLS.
Check the `network.tls.enabled` setting.