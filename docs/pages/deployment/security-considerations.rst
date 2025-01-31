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
