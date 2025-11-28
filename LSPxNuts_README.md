# LSPxNuts Proof of Concept

This is a branch that for the Proof of Concept of the LSPxNuts project.

It adds or alters the following functionality versus the mainstream Nuts node:

- OAuth2 `vp_bearer` token exchange: read presentation definition from local definitions instead of fetching it from the remote authorization server.
  LSP doesn't support presentation definitions, meaning that we need to look it up locally.