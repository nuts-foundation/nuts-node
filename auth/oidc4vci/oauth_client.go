package oidc4vci

import (
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/nuts-foundation/nuts-node/auth/api/oidc4vci_v0/types"
	"io"
	"net/http"
	"net/url"
)

// OAuth2Client defines a generic OAuth2 client.
type OAuth2Client interface {
	// RequestAccessToken requests an access token from the Authorization Server.
	RequestAccessToken(grantType string, params map[string]string) (*types.OIDCTokenResponse, error)
}

var _ OAuth2Client = &httpOAuth2Client{}

type httpOAuth2Client struct {
	metadata   types.OIDCProviderMetadata
	httpClient http.Client
}

func (c httpOAuth2Client) RequestAccessToken(grantType string, params map[string]string) (*types.OIDCTokenResponse, error) {
	values := url.Values{}
	values.Add("grant_type", grantType)
	for key, value := range params {
		values.Add(key, value)
	}

	httpResponse, err := c.httpClient.PostForm(*c.metadata.TokenEndpoint, values)
	defer httpResponse.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("http request error: %w", err)
	}
	if httpResponse.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected HTTP response code")
	}
	responseBody, _ := io.ReadAll(httpResponse.Body)
	accessTokenResponse := types.OIDCTokenResponse{}
	err = json.Unmarshal(responseBody, &accessTokenResponse)
	if err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	return &accessTokenResponse, nil
}
