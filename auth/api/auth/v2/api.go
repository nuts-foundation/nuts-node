package v2

import (
	"context"
	"embed"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"net/http"
	"sync"
)

var _ core.Routable = &Wrapper{}
var _ StrictServerInterface = &Wrapper{}

//go:embed assets
var assets embed.FS

// Wrapper handles OAuth2 flows.
type Wrapper struct {
	VCR      vcr.VCR
	Auth     auth.AuthenticationServices
	sessions *SessionManager
}

func New(authInstance auth.AuthenticationServices, vcrInstance vcr.VCR) *Wrapper {
	sessionManager := &SessionManager{sessions: new(sync.Map)}
	return &Wrapper{
		sessions: sessionManager,
		Auth:     authInstance,
		VCR:      vcrInstance,
	}
}

func (r Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(r, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, vcr.ModuleName+"/v2")
				// TODO: Do we need a generic error handler?
				// ctx.Set(core.ErrorWriterContextKey, &protocolErrorWriter{})
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, args interface{}) (interface{}, error) {
				if !r.Auth.V2APIEnabled() {
					return nil, core.Error(http.StatusForbidden, "Access denied")
				}
				return f(ctx, args)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, vcr.ModuleName+"/v2", operationID)
		},
	}))
}

// HandleTokenRequest handles calls to the token endpoint for exchanging a grant (e.g authorization code or pre-authorized code) for an access token.
func (r Wrapper) HandleTokenRequest(ctx context.Context, request HandleTokenRequestRequestObject) (HandleTokenRequestResponseObject, error) {
	switch request.Body.GrantType {
	case "authorization_code":
		// Options:
		// - OpenID4VCI
		// - OpenID4VP, vp_token is sent in Token Response
	case "vp_token":
		// Options:
		// - service-to-service vp_token flow
	case "urn:ietf:params:oauth:grant-type:pre-authorized_code":
		// Options:
		// - OpenID4VCI
	default:
		return nil, openid4vci.Error{
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
			//Description: "invalid grant type",
		}
	}

	// TODO: Handle?
	//scope, err := handler(request.Body.AdditionalProperties)
	//if err != nil {
	//	return nil, err
	//}
	// TODO: Generate access token with scope
	return HandleTokenRequest200JSONResponse(TokenResponse{
		AccessToken: "",
	}), nil
}

// HandleAuthorizeRequest handles calls to the authorization endpoint for starting an authorization code flow.
func (r Wrapper) HandleAuthorizeRequest(ctx context.Context, request HandleAuthorizeRequestRequestObject) (HandleAuthorizeRequestResponseObject, error) {
	// Create session object to be passed to handler
	session := &Session{
		// TODO: Validate client ID
		ClientID: request.Body.ClientId,
	}
	// TODO: Validate scope?
	if request.Body.Scope != nil {
		session.Scope = *request.Body.Scope
	}
	if request.Body.State != nil {
		session.ClientState = *request.Body.State
	}
	// TODO: Validate redirect URI
	if request.Body.RedirectUri != nil {
		// TODO: Validate according to https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
		session.RedirectURI = *request.Body.RedirectUri
	} else {
		// TODO: Spec says that the redirect URI is optional, but it's not clear what to do if it's not provided.
		//       See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
		return nil, errors.New("missing redirect URI")
	}

	switch request.Body.ResponseType {
	case "code":
		// Options:
		// - Regular authorization code flow for EHR data access through access token, authentication of end-user using OpenID4VP.
		// - OpenID4VCI; authorization code flow for credential issuance to (end-user) wallet
		// - OpenID4VP, vp_token is sent in Token Response; authorization code flow for presentation exchange (not required a.t.m.)
		// TODO: Switch on parameters to right flow
	case "vp_token":
		// Options:
		// - OpenID4VP flow, vp_token is sent in Authorization Response
		// TODO: Check parameters for right flow
		// TODO: Do we actually need this? (probably not)
	case "vp_token id_token":
		// Options:
		// - OpenID4VP+SIOP flow, vp_token is sent in Authorization Response
		// TODO: Check parameters for right flow
	default:
		// TODO: This should be a redirect?
		return nil, openid4vci.Error{
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
			//Description: "invalid/unsupported response_type",
		}
	}

	// No handler could handle the request
	// TODO: This should be a redirect?
	return nil, openid4vci.Error{
		Code:       openid4vci.InvalidRequest,
		StatusCode: http.StatusBadRequest,
		//Description: "missing or invalid parameters",
	}
}

func (r Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	// TODO: Start service-to-service vp_token flow
	return nil, nil
}

func (r Wrapper) RequestPresentation(ctx context.Context, request RequestPresentationRequestObject) (RequestPresentationResponseObject, error) {
	// TODO: Start OpenID4VP flow
	return nil, nil
}
