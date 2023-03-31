package oidc4vci

import (
	"context"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
	"net/http"
	"net/url"
	"strings"
)

// OAuth2Client defines a generic OAuth2 client.
type OAuth2Client interface {
	// RequestAccessToken requests an access token from the Authorization Server.
	RequestAccessToken(grantType string, params map[string]string) (*types.OIDCTokenResponse, error)
}

var _ OAuth2Client = &httpOAuth2Client{}

type httpOAuth2Client struct {
	metadata   types.OIDCProviderMetadata
	httpClient *http.Client
}

func (c httpOAuth2Client) RequestAccessToken(grantType string, params map[string]string) (*types.OIDCTokenResponse, error) {
	values := url.Values{}
	values.Add("grant_type", grantType)
	for key, value := range params {
		values.Add(key, value)
	}
	httpRequest, _ := http.NewRequestWithContext(context.Background(), "POST", c.metadata.TokenEndpoint, strings.NewReader(values.Encode()))
	httpRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	var accessTokenResponse types.OIDCTokenResponse
	err := httpDo(c.httpClient, httpRequest, &accessTokenResponse)
	if err != nil {
		return nil, err
	}
	return &accessTokenResponse, nil
}
