package oidc4vci

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// OAuth2Client defines a generic OAuth2 client.
type OAuth2Client interface {
	// RequestAccessToken requests an access token from the Authorization Server.
	RequestAccessToken(grantType string, params map[string]string) (*TokenResponse, error)
}

var _ OAuth2Client = &httpOAuth2Client{}

type httpOAuth2Client struct {
	metadata   ProviderMetadata
	httpClient *http.Client
}

func (c httpOAuth2Client) RequestAccessToken(grantType string, params map[string]string) (*TokenResponse, error) {
	values := url.Values{}
	values.Add("grant_type", grantType)
	for key, value := range params {
		values.Add(key, value)
	}
	httpRequest, _ := http.NewRequestWithContext(context.Background(), "POST", c.metadata.TokenEndpoint, strings.NewReader(values.Encode()))
	httpRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	var accessTokenResponse TokenResponse
	err := httpDo(c.httpClient, httpRequest, &accessTokenResponse)
	if err != nil {
		return nil, err
	}
	return &accessTokenResponse, nil
}
