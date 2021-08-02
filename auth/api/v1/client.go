package v1

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/core"
)

type oauthAPIError struct {
	err        error
	statusCode int
}

func (err *oauthAPIError) StatusCode() int {
	return err.statusCode
}

func (err *oauthAPIError) Error() string {
	return err.err.Error()
}

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	Timeout time.Duration
	client  ClientInterface
}

// NewHTTPClient creates a new HTTPClient using the generated OAS client
func NewHTTPClient(serverAddress string, timeout time.Duration, opts ...ClientOption) (*HTTPClient, error) {
	client, err := NewClientWithResponses(serverAddress, opts...)
	if err != nil {
		return nil, err
	}

	return &HTTPClient{Timeout: timeout, client: client}, nil
}

// CreateAccessToken creates an access token and overrides the url by the 'endpointURL' input argument
func (h HTTPClient) CreateAccessToken(endpointURL url.URL, bearerToken string) (*AccessTokenResponse, error) {
	ctx, cancel := h.withTimeout()
	defer cancel()

	values := url.Values{}
	values.Set("assertion", bearerToken)
	values.Set("grant_type", auth.JwtBearerGrantType)

	response, err := h.client.CreateAccessTokenWithBody(
		ctx,
		"application/x-www-form-urlencoded",
		strings.NewReader(values.Encode()),
		withURL(endpointURL),
	)
	if err != nil {
		return nil, err
	}

	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, &oauthAPIError{err: err, statusCode: response.StatusCode}
	}

	result, err := ParseCreateAccessTokenResponse(response)
	if err != nil {
		return nil, err
	}

	return result.JSON200, nil
}

func (h HTTPClient) withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), h.Timeout)
}

func withURL(uri url.URL) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		req.URL = &uri
		return nil
	}
}
