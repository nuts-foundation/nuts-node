/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package iam

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

var _ core.Routable = &Wrapper{}
var _ StrictServerInterface = &Wrapper{}

//go:embed assets
var assets embed.FS

// Wrapper handles OAuth2 flows.
type Wrapper struct {
	vcr                     vcr.VCR
	vdr                     vdr.DocumentOwner
	auth                    auth.AuthenticationServices
	sessions                *SessionManager
	presentationDefinitions presentationDefinitionRegistry
	templates               *template.Template
}

func New(authInstance auth.AuthenticationServices, vcrInstance vcr.VCR, vdrInstance vdr.DocumentOwner) *Wrapper {
	templates := template.New("oauth2 templates")
	_, err := templates.ParseFS(assets, "assets/*.html")
	if err != nil {
		panic(err)
	}
	return &Wrapper{
		sessions:                &SessionManager{sessions: new(sync.Map)},
		auth:                    authInstance,
		vcr:                     vcrInstance,
		vdr:                     vdrInstance,
		presentationDefinitions: nutsPresentationDefinitionRegistry{},
		templates:               templates,
	}
}

func (r Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(r, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, auth.ModuleName+"/v2")
				// Add http.Request to context, to allow reading URL query parameters
				requestCtx := context.WithValue(ctx.Request().Context(), "http-request", ctx.Request())
				ctx.SetRequest(ctx.Request().WithContext(requestCtx))
				// TODO: Do we need a generic error handler?
				// ctx.Set(core.ErrorWriterContextKey, &protocolErrorWriter{})
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, args interface{}) (interface{}, error) {
				if !r.auth.V2APIEnabled() {
					return nil, core.Error(http.StatusForbidden, "Access denied")
				}
				return f(ctx, args)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, auth.ModuleName+"/v2", operationID)
		},
	}))
	// The following handler is of the OpenID4VCI wallet which is called by the holder (wallet owner)
	// when accepting an OpenID4VP authorization request.
	router.POST("/iam/:did/openid4vp_authz_accept", func(echoCtx echo.Context) error {
		return r.handlePresentationRequestAccept(echoCtx)
	}, audit.Middleware(vcr.ModuleName+"/v2", "openid4vp_authz_accept"))
	// The following handler is of the OpenID4VP verifier where the browser will be redirected to by the wallet,
	// after completing a presentation exchange.
	router.GET("/iam/:did/openid4vp_completed", func(echoCtx echo.Context) error {
		// TODO: error case
		return r.handlePresentationRequestCompleted(echoCtx)
	}, audit.Middleware(vcr.ModuleName+"/v2", "openid4vp_completed"))
	// The following 2 handlers are used to test/demo the OpenID4VP flow.
	// - GET renders an HTML page with a form to start the flow.
	// - POST handles the form submission, initiating the flow.
	router.GET("/iam/:did/openid4vp_demo", func(echoCtx echo.Context) error {
		requestURL := *echoCtx.Request().URL
		requestURL.Host = echoCtx.Request().Host
		requestURL.Scheme = "http"
		verifierID := requestURL.String()
		verifierID, _ = strings.CutSuffix(verifierID, "/openid4vp_demo")

		buf := new(bytes.Buffer)
		if err := r.templates.ExecuteTemplate(buf, "openid4vp_demo.html", struct {
			VerifierID string
			WalletID   string
		}{
			VerifierID: verifierID,
			WalletID:   verifierID,
		}); err != nil {
			return err
		}
		return echoCtx.HTML(http.StatusOK, buf.String())
	})
	router.POST("/iam/:did/openid4vp_demo", func(echoCtx echo.Context) error {
		verifierID := echoCtx.FormValue("verifier_id")
		if verifierID == "" {
			return errors.New("missing verifier_id")
		}
		walletID := echoCtx.FormValue("wallet_id")
		if walletID == "" {
			return errors.New("missing wallet_id")
		}
		scope := echoCtx.FormValue("scope")
		if scope == "" {
			return errors.New("missing scope")
		}
		walletURL, _ := url.Parse(walletID)
		verifierURL, _ := url.Parse(verifierID)
		return r.sendPresentationRequest(
			echoCtx.Request().Context(), echoCtx.Response(), scope,
			*walletURL.JoinPath("openid4vp_completed"), *verifierURL, *walletURL,
		)
	})
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
		// TODO: Don't use openid4vci package for errors
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
	ownDID, err := did.ParseDID(request.Did)
	if err != nil {
		// TODO: Redirect instead
		return nil, err
	}
	// Create session object to be passed to handler

	// Workaround: deepmap codegen doesn't support dynamic query parameters.
	//             See https://github.com/deepmap/oapi-codegen/issues/1129
	httpRequest := ctx.Value("http-request").(*http.Request)
	params := make(map[string]string)
	for key, value := range httpRequest.URL.Query() {
		params[key] = value[0]
	}
	session := &Session{
		// TODO: Validate client ID
		ClientID: params[clientIDParam],
		// TODO: Validate scope
		Scope:       params[scopeParam],
		ClientState: params[stateParam],
		ServerState: map[string]interface{}{},
		// TODO: Validate according to https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
		RedirectURI: params[redirectURIParam],
		OwnDID:      *ownDID,
	}
	if session.RedirectURI == "" {
		// TODO: Spec says that the redirect URI is optional, but it's not clear what to do if it's not provided.
		//       Threat models say it's unsafe to omit redirect_uri.
		//       See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
		return nil, errors.New("missing redirect URI")
	}

	switch request.Body.ResponseType {
	case responseTypeCode:
		// Options:
		// - Regular authorization code flow for EHR data access through access token, authentication of end-user using OpenID4VP.
		// - OpenID4VCI; authorization code flow for credential issuance to (end-user) wallet
		// - OpenID4VP, vp_token is sent in Token Response; authorization code flow for presentation exchange (not required a.t.m.)
		// TODO: Switch on parameters to right flow
	case responseTypeVPToken:
		// Options:
		// - OpenID4VP flow, vp_token is sent in Authorization Response
		// TODO: Check parameters for right flow
		// TODO: Do we actually need this? (probably not)
	case responseTypeVPIDToken:
		// Options:
		// - OpenID4VP+SIOP flow, vp_token is sent in Authorization Response
		return r.handlePresentationRequest(params, session)
	default:
		// TODO: This should be a redirect?
		// TODO: Don't use openid4vci package for errors
		return nil, openid4vci.Error{
			Code:       openid4vci.InvalidRequest,
			StatusCode: http.StatusBadRequest,
			//Description: "invalid/unsupported response_type",
		}
	}

	// No handler could handle the request
	// TODO: This should be a redirect?
	// TODO: Don't use openid4vci package for errors
	return nil, openid4vci.Error{
		Code:       openid4vci.InvalidRequest,
		StatusCode: http.StatusBadRequest,
		//Description: "missing or invalid parameters",
	}
}

// GetOAuthAuthorizationServerMetadata returns the Authorization Server's metadata
func (r Wrapper) GetOAuthAuthorizationServerMetadata(ctx context.Context, request GetOAuthAuthorizationServerMetadataRequestObject) (GetOAuthAuthorizationServerMetadataResponseObject, error) {
	id, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, core.InvalidInputError("authz server metadata: %w", err)
	}

	if id.Method != "nuts" {
		return nil, core.InvalidInputError("authz server metadata: only did:nuts is supported")
	}

	owned, err := r.vdr.IsOwner(ctx, *id)
	if err != nil {
		if didservice.IsFunctionalResolveError(err) {
			return nil, core.NotFoundError("authz server metadata: %w", err)
		}
		log.Logger().WithField("did", id.String()).Errorf("authz server metadata: failed to assert ownership of did: %s", err.Error())
		return nil, core.Error(500, "authz server metadata: %w", err)
	}
	if !owned {
		return nil, core.NotFoundError("authz server metadata: did not owned")
	}

	identity := r.auth.PublicURL().JoinPath("iam", id.WithoutURL().String())

	return GetOAuthAuthorizationServerMetadata200JSONResponse(authorizationServerMetadata(*identity)), nil
}
