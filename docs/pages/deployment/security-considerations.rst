.. _security-considerations:

Security Considerations
#######################

Please consult the topics below for various security considerations.

Endpoint Security
*****************

It's important to prevent outside access to the internal API's. By default these are available from ``127.0.0.1:8081`` and are not protected with API security.
When exposing the external APIs to your internal network, take the appropriate measures to secure the API's (SSH, API security, etc).

In addition to securing the internal APIs, it's recommended to limit access to the public APIs using a reverse proxy.
This will allow you to control access to the public APIs, do TLS termination and add additional security measures.
Block any path that's not used by the Nuts node.

.. _ssrf-protection:

Outbound HTTP and SSRF protection
*********************************

The Nuts node fetches URLs supplied by other parties, for example DID documents, OAuth metadata and
Discovery Service endpoints. An attacker could register a URL that resolves to an address inside your
network and let the node request it on their behalf. This is known as Server-Side Request Forgery (SSRF).

In strict mode the node refuses outbound HTTP connections to non-public addresses: loopback,
private (RFC 1918), carrier-grade NAT, link-local, unique local, and the other special-purpose ranges
published in the IANA
`IPv4 <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>`_ and
`IPv6 <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>`_
special-purpose address registries. The check runs at connect time against the resolved IP address, so it
also covers redirects and cannot be bypassed with DNS rebinding. Cloud provider metadata endpoints (such as
``169.254.169.254`` and Azure's ``168.63.129.16``) are always blocked, following the
`OWASP SSRF prevention cheat sheet <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>`_.
Redirects that downgrade from HTTPS to HTTP are refused as well.

A blocked request fails with an error like::

    strictmode: blocked connection to non-public address 10.0.0.5

Allowing internal ranges
========================

If a legitimate flow targets a private address, for example an internal OpenID4VCI issuer or an OAuth
flow that stays inside your network, then permit that range with ``http.client.allowedinternalcidrs``.
If part of an allowed range must stay unreachable, then deny that part with ``http.client.deniedcidrs``;
denied ranges take precedence:

.. code-block:: yaml

    http:
      client:
        allowedinternalcidrs:
          - 10.0.0.0/8
        deniedcidrs:
          - 10.5.0.0/16

Keep allowed ranges as narrow as possible. Every address in an allowed range becomes reachable for any
URL an external party can make the node fetch.

Blocking additional ranges
==========================

Some networks use publicly routable addresses for internal-only systems. Public addresses are not
covered by the built-in guard, so add such ranges to ``http.client.deniedcidrs`` explicitly.

The built-in blocks for cloud metadata endpoints cannot be lifted with ``allowedinternalcidrs``.
Both options only apply in strict mode; without strict mode the SSRF guard is disabled.

D(D)oS Protection
*****************

Consider implementing (D)DoS protection on the application layer for all public endpoints.
Monitor and log the following metrics:

- Number of requests per second
- Number of requests from a single IP address
- Amount of non-20x responses

Any outliers should be investigated.

Maximum client body size for public-facing POST APIs
****************************************************

Various parts of the Nuts Node API allow for POST requests. To prevent abuse, you should limit the size of the request body.
The following public APIs accept POST requests:

- ``/discovery/{service}``
- ``/oauth2/{subjectID}/token``
- ``/oauth2/{subjectID}/request.jwt/{id}``
- ``/oauth2/{subjectID}/response``

To prevent malicious uploads, you MUST limit the size of the requests.
As a safeguard, the Nuts node will also limit the size of request bodies.

For example, Nginx has a configuration directive to limit the size of the request body:

.. code-block:: nginx

    client_max_body_size 1M;

The actual limit depends on your use case. It should be large enough for Verifiable Presentations to be uploaded, but small enough to prevent abuse.

Key rotation
************

It's important to have a key rotation policy in place. The Nuts node uses keys for various signing operations.
These operations are numerous and therefore keys should be rotated regularly.

Using did:web
*************

The ``did:web`` method allows for easier integration with existing web infrastructure. However, it's also less secure and vulnerable to domain takeover.
When using ``did:web``, you should consider the following:

- Protect your domain from takeover. Make sure it's locked for a year after cancelling the domain.
- Monitor calls to ``**/did.json`` on the domain and make sure they are handled by the Nuts Node.
- Using Hashicorp Vault or Microsoft Azure Key Vault to store the private keys is even more important when using ``did:web``.
- Use DNS over HTTPS and enable DNSSEC.
