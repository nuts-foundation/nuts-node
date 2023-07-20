This test suite tests the credential issuance over OpenID Connect 4 Verifiable Credentials. It tests the following cases:

1. Issuer initiated: node A issued a credential to node B using a credential offer and pre-authorized code.
2. Network issuance: node A has OpenID4VCI disabled and issues a credential to node B that does support OpenID4VCI issued credentials. See https://github.com/nuts-foundation/nuts-node/issues/2362
