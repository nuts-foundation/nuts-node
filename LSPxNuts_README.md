# LSPxNuts Proof of Concept

This is a branch that for the Proof of Concept of the LSPxNuts project.

It adds or alters the following functionality versus the mainstream Nuts node:

- OAuth2 `vp_bearer` token exchange: read presentation definition from local definitions instead of fetching it from the remote authorization server.
  LSP doesn't support presentation definitions, meaning that we need to look it up locally.
- Add support for JWT bearer grant type. If the server supports this, it uses this grant type instead of the Nuts-specific vp_token-bearer grant type.
- Add CA certificates of Sectigo (root CA, OV and EV intermediate CA), because they're used by AORTA-LSP.
- Fix marshalling of Verifiable Presentations in JWT format; `type` was marshalled as JSON-LD (single-entry-array was replaced by string)
- Add `policy_id` field to access token request to specify the Presentation Definition that should be used.
  The `scope` can then be specified as whatever the use case requires (e.g. SMART on FHIR-esque scopes).
- Relax `did:x509` key usage check: the certificate from UZI smart cards that is used to sign credentials, doesn't have `serverAuth` key usage, only `digitalSignature`.
  This broke, since we didn't specify the key usage, but `x509.Verify()` expects key usage `serverAuth` to be present by default.
- Add support for `RS256` (RSA 2048) signatures, since that's what UZI smart cards produce.