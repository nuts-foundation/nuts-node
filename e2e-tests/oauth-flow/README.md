This test suite tests the Nuts OAuth flow.

## Tests

### rfc002
Tests the OAuth 2.0 flow as specified by Nuts RFC002, using mTLS client authentication.

### rfc021
Tests the OAuth 2.0 vp_token bearer grant type as specified by Nuts RFC021.
Two nodes (nodeA as resource server, nodeB as client) exchange a NutsOrganizationCredential and NutsEmployeeCredential via a Verifiable Presentation with a DIF Presentation Exchange submission.
Runs on all supported databases (SQLite, PostgreSQL, MySQL, SQL Server).

### didx509
Tests the RFC021 flow using an X.509 credential (`NutsSelfSignedCertificateCredential`) instead of a DID-based credential.

### jwt-bearer
Tests the OAuth 2.0 JWT bearer grant type (RFC7523).
NodeB requests an access token from nodeA by presenting a NutsOrganizationCredential in a Verifiable Presentation as the `assertion` parameter, without a Presentation Exchange submission.
The server advertises `urn:ietf:params:oauth:grant-type:jwt-bearer` in its authorization server metadata, causing the client to automatically select this grant type over the default vp_token-bearer flow.
Runs on SQLite only (no database-specific behavior).

### openid4vp
Tests the OpenID for Verifiable Presentations (OpenID4VP) flow.

### statuslist2021
Tests credential revocation via the StatusList2021 mechanism.
