package iam

import (
	"context"
	"crypto/tls"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
	"time"
)

var _ MitzXNutsClient = (*OpenID4VPClient)(nil)

type OpenID4VPMitzXNutsClient struct {
	httpClientTimeout time.Duration
	httpClientTLS     *tls.Config
	jwtSigner         nutsCrypto.JWTSigner
	keyResolver       resolver.KeyResolver
	strictMode        bool
	wallet            holder.Wallet
}

func (c *OpenID4VPClient) AccessTokenOid4vci(ctx context.Context, clientId string, tokenEndpoint string, redirectUri string, code string, pkceCodeVerifier *string) (*oauth.Oid4vciTokenResponse, error) {
	iamClient := c.newHTTPClient()
	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set(oauth.GrantTypeParam, oauth.AuthorizationCodeGrantType)
	data.Set(oauth.CodeParam, code)
	data.Set("redirect_uri", redirectUri)
	if pkceCodeVerifier != nil {
		data.Set("code_verifier", *pkceCodeVerifier)
	}
	presentationDefinitionURL, err := url.Parse(tokenEndpoint)
	if err != nil {
		return nil, err
	}

	rsp, err := iamClient.AccessTokenOid4vci(ctx, *presentationDefinitionURL, data)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *OpenID4VPClient) OpenIdConfiguration(ctx context.Context, serverURL url.URL) (*oauth.OpenIDConfigurationMetadata, error) {
	iamClient := c.newHTTPClient()
	rsp, err := iamClient.OpenIdConfiguration(ctx, serverURL)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *OpenID4VPClient) OpenIdCredentialIssuerMetadata(ctx context.Context, webDID did.DID) (*oauth.OpenIDCredentialIssuerMetadata, error) {
	iamClient := c.newHTTPClient()
	rsp, err := iamClient.OpenIdCredentialIssuerMetadata(ctx, webDID)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *OpenID4VPClient) VerifiableCredentials(ctx context.Context, credentialEndpoint string, accessToken string, proofJwt string) (*CredentialResponse, error) {
	iamClient := c.newHTTPClient()
	rsp, err := iamClient.VerifiableCredentials(ctx, credentialEndpoint, accessToken, proofJwt)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}
