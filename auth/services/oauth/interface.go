package oauth

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"net/url"
)

// Client is the client interface for the OAuth service
type Client interface {
	// Configure sets up the client. Enable secureMode to have it behave more safe (e.g., sanitize internal errors).
	Configure(clockSkewInMilliseconds int, secureMode bool) error
	// CreateAccessToken is called by remote Nuts nodes to create an access token,
	// which can be used to access the local organization's XIS resources.
	// It returns an oauth.ErrorResponse rather than a regular Go error, because the errors that may be returned are tightly specified.
	CreateAccessToken(request services.CreateAccessTokenRequest) (*services.AccessTokenResult, *ErrorResponse)
	CreateJwtGrant(request services.CreateJwtGrantRequest) (*services.JwtBearerTokenResult, error)
	GetOAuthEndpointURL(service string, authorizer did.DID) (url.URL, error)
	IntrospectAccessToken(token string) (*services.NutsAccessToken, error)
}
