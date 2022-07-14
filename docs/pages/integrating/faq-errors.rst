.. _faq-errors:

Frequently Encountered Errors
#############################

This section lists commonly seen errors, what they mean and what to do about it.

Error: `connection closed before server preface received`
*********************************************************

When connecting to a remote node, the following error can occur:

    Couldn't connect to peer, reconnecting in XYZ seconds (peer=some.domain.nl:5555,err=unable to connect: context deadline exceeded: connection closed before server preface received)

This indicates the server is using TLS, but the local node is trying to connect without TLS.
Check the `network.tls.enabled` setting.

Error: `JWT signing key not present on this node`
*************************************************

When inspecting an access token, the following error can occur:

    Error while inspecting access token (error: JWT signing key not present on this node)

This indicates the JWT token you send to the Nuts node can't be introspected by the Nuts node,
because it can't find the private key that was used to create the token. You probably:

# Try to introspect a token that your node didn't create: only node that issued the token can introspect it. Or:
# Your node's private key storage is corrupt and your node lost access to its private keys (less probable).
