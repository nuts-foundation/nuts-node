package iam

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"net/url"
)

type MitzXNutsClient interface {
	AccessTokenOid4vci(ctx context.Context, clientId string, tokenEndpoint string, redirectUri string, code string, pkceCodeVerifier *string) (*oauth.Oid4vciTokenResponse, error)

	OpenIdConfiguration(ctx context.Context, serverURL url.URL) (*oauth.OpenIDConfigurationMetadata, error)

	OpenIdCredentialIssuerMetadata(ctx context.Context, webDID did.DID) (*oauth.OpenIDCredentialIssuerMetadata, error)

	VerifiableCredentials(ctx context.Context, credentialEndpoint string, accessToken string, proofJwt string) (*CredentialResponse, error)
}
