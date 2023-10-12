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
	"context"
	"embed"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"html/template"
	"net/http"
	"strings"
	"sync"
)

var _ core.Routable = &Wrapper{}
var _ StrictServerInterface = &Wrapper{}

const apiPath = "iam"
const apiModuleName = auth.ModuleName + "/" + apiPath
const httpRequestContextKey = "http-request"

//go:embed assets
var assets embed.FS

// Wrapper handles OAuth2 flows.
type Wrapper struct {
	vcr       vcr.VCR
	vdr       vdr.VDR
	auth      auth.AuthenticationServices
	sessions  *SessionManager
	templates *template.Template
}

func New(authInstance auth.AuthenticationServices, vcrInstance vcr.VCR, vdrInstance vdr.VDR) *Wrapper {
	templates := template.New("oauth2 templates")
	_, err := templates.ParseFS(assets, "assets/*.html")
	if err != nil {
		panic(err)
	}
	return &Wrapper{
		sessions:  &SessionManager{sessions: new(sync.Map)},
		auth:      authInstance,
		vcr:       vcrInstance,
		vdr:       vdrInstance,
		templates: templates,
	}
}

func (r Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(r, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				return r.middleware(ctx, request, operationID, f)
			}
		},
	}))
	auditMiddleware := audit.Middleware(apiModuleName)
	// The following handler is of the OpenID4VCI wallet which is called by the holder (wallet owner)
	// when accepting an OpenID4VP authorization request.
	router.POST("/iam/:did/openid4vp_authz_accept", r.handlePresentationRequestAccept, auditMiddleware)
	// The following handler is of the OpenID4VP verifier where the browser will be redirected to by the wallet,
	// after completing a presentation exchange.
	router.GET("/iam/:did/openid4vp_completed", r.handlePresentationRequestCompleted, auditMiddleware)
	// The following 2 handlers are used to test/demo the OpenID4VP flow.
	// - GET renders an HTML page with a form to start the flow.
	// - POST handles the form submission, initiating the flow.
	router.GET("/iam/:did/openid4vp_demo", r.handleOpenID4VPDemoLanding, auditMiddleware)
	router.POST("/iam/:did/openid4vp_demo", r.handleOpenID4VPDemoSendRequest, auditMiddleware)
}

func (r Wrapper) middleware(ctx echo.Context, request interface{}, operationID string, f StrictHandlerFunc) (interface{}, error) {
	ctx.Set(core.OperationIDContextKey, operationID)
	ctx.Set(core.ModuleNameContextKey, apiModuleName)

	if !r.auth.V2APIEnabled() {
		return nil, core.Error(http.StatusForbidden, "Access denied")
	}

	// Add http.Request to context, to allow reading URL query parameters
	requestCtx := context.WithValue(ctx.Request().Context(), httpRequestContextKey, ctx.Request())
	ctx.SetRequest(ctx.Request().WithContext(requestCtx))
	if strings.HasPrefix(ctx.Request().URL.Path, "/iam/") {
		ctx.Set(core.ErrorWriterContextKey, &oauth2ErrorWriter{})
	}
	audit.StrictMiddleware(f, apiModuleName, operationID)
	return f(ctx, request)
}

// HandleTokenRequest handles calls to the token endpoint for exchanging a grant (e.g authorization code or pre-authorized code) for an access token.
func (r Wrapper) HandleTokenRequest(ctx context.Context, request HandleTokenRequestRequestObject) (HandleTokenRequestResponseObject, error) {
	switch request.Body.GrantType {
	case "authorization_code":
		// Options:
		// - OpenID4VCI
		// - OpenID4VP, vp_token is sent in Token Response
		return nil, OAuth2Error{
			Code:        UnsupportedGrantType,
			Description: "not implemented yet",
		}
	case "vp_token":
		// Options:
		// - service-to-service vp_token flow
		return nil, OAuth2Error{
			Code:        UnsupportedGrantType,
			Description: "not implemented yet",
		}
	case "urn:ietf:params:oauth:grant-type:pre-authorized_code":
		// Options:
		// - OpenID4VCI
		return nil, OAuth2Error{
			Code:        UnsupportedGrantType,
			Description: "not implemented yet",
		}
	default:
		return nil, OAuth2Error{
			Code: UnsupportedGrantType,
		}
	}
}

// HandleAuthorizeRequest handles calls to the authorization endpoint for starting an authorization code flow.
func (r Wrapper) HandleAuthorizeRequest(ctx context.Context, request HandleAuthorizeRequestRequestObject) (HandleAuthorizeRequestResponseObject, error) {
	ownDID := idToDID(request.Id)
	// Create session object to be passed to handler

	// Workaround: deepmap codegen doesn't support dynamic query parameters.
	//             See https://github.com/deepmap/oapi-codegen/issues/1129
	httpRequest := ctx.Value(httpRequestContextKey).(*http.Request)
	params := make(map[string]string)
	for key, value := range httpRequest.URL.Query() {
		params[key] = value[0]
	}
	session := createSession(params, ownDID)
	if session.RedirectURI == "" {
		// TODO: Spec says that the redirect URI is optional, but it's not clear what to do if it's not provided.
		//       Threat models say it's unsafe to omit redirect_uri.
		//       See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
		return nil, OAuth2Error{
			Code:        InvalidRequest,
			Description: "redirect_uri is required",
		}
	}

	switch session.ResponseType {
	case responseTypeCode:
		// Options:
		// - Regular authorization code flow for EHR data access through access token, authentication of end-user using OpenID4VP.
		// - OpenID4VCI; authorization code flow for credential issuance to (end-user) wallet
		// - OpenID4VP, vp_token is sent in Token Response; authorization code flow for presentation exchange (not required a.t.m.)
		// TODO: Switch on parameters to right flow
		panic("not implemented")
	case responseTypeVPToken:
		// Options:
		// - OpenID4VP flow, vp_token is sent in Authorization Response
		// TODO: Check parameters for right flow
		// TODO: Do we actually need this? (probably not)
		panic("not implemented")
	case responseTypeVPIDToken:
		// Options:
		// - OpenID4VP+SIOP flow, vp_token is sent in Authorization Response
		return r.handlePresentationRequest(params, session)
	default:
		// TODO: This should be a redirect?
		return nil, OAuth2Error{
			Code:        UnsupportedResponseType,
			RedirectURI: session.RedirectURI,
		}
	}
}

// OAuthAuthorizationServerMetadata returns the Authorization Server's metadata
func (r Wrapper) OAuthAuthorizationServerMetadata(ctx context.Context, request OAuthAuthorizationServerMetadataRequestObject) (OAuthAuthorizationServerMetadataResponseObject, error) {
	ownDID := idToDID(request.Id)
	owned, err := r.vdr.IsOwner(ctx, ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return nil, core.NotFoundError("authz server metadata: %w", err)
		}
		log.Logger().WithField("did", ownDID.String()).Errorf("authz server metadata: failed to assert ownership of did: %s", err.Error())
		return nil, core.Error(500, "authz server metadata: %w", err)
	}
	if !owned {
		return nil, core.NotFoundError("authz server metadata: did not owned")
	}

	identity := r.auth.PublicURL().JoinPath("iam", request.Id)

	return OAuthAuthorizationServerMetadata200JSONResponse(authorizationServerMetadata(*identity)), nil
}

func (r Wrapper) GetWebDID(ctx context.Context, request GetWebDIDRequestObject) (GetWebDIDResponseObject, error) {
	baseURL := *(r.auth.PublicURL().JoinPath(apiPath))
	ownDID := idToDID(request.Id)

	document, err := r.vdr.DeriveWebDIDDocument(ctx, baseURL, ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return GetWebDID404Response{}, nil
		}
		log.Logger().WithError(err).Errorf("Could not resolve Nuts DID: %s", ownDID.String())
		return nil, errors.New("unable to resolve DID")
	}
	return GetWebDID200JSONResponse(*document), nil
}

// OAuthClientMetadata returns the OAuth2 Client metadata for the request.Id if it is managed by this node.
func (r Wrapper) OAuthClientMetadata(ctx context.Context, request OAuthClientMetadataRequestObject) (OAuthClientMetadataResponseObject, error) {
	ownDID := idToDID(request.Id)
	owned, err := r.vdr.IsOwner(ctx, ownDID)
	if err != nil {
		log.Logger().WithField("did", ownDID.String()).Errorf("oauth metadata: failed to assert ownership of did: %s", err.Error())
		return nil, core.Error(500, err.Error())
	}
	if !owned {
		return nil, core.NotFoundError("did not owned")
	}

	identity := r.auth.PublicURL().JoinPath("iam", request.Id)

	return OAuthClientMetadata200JSONResponse(clientMetadata(*identity)), nil
}
func (r Wrapper) PresentationDefinition(_ context.Context, request PresentationDefinitionRequestObject) (PresentationDefinitionResponseObject, error) {
	if len(request.Params.Scope) == 0 {
		return PresentationDefinition200JSONResponse(PresentationDefinition{}), nil
	}

	// todo: only const scopes supported, scopes with variable arguments not supported yet
	// todo: we only take the first scope as main scope, when backends are introduced we need to use all scopes and send them as one to the backend.
	scopes := strings.Split(request.Params.Scope, " ")
	presentationDefinition := r.auth.PresentationDefinitions().ByScope(scopes[0])
	if presentationDefinition == nil {
		return PresentationDefinition400JSONResponse{
			Code: "invalid_scope",
		}, nil
	}

	return PresentationDefinition200JSONResponse(*presentationDefinition), nil
}

func createSession(params map[string]string, ownDID did.DID) *Session {
	session := &Session{
		// TODO: Validate client ID
		ClientID: params[clientIDParam],
		// TODO: Validate scope
		Scope:       params[scopeParam],
		ClientState: params[stateParam],
		ServerState: map[string]interface{}{},
		// TODO: Validate according to https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
		RedirectURI:  params[redirectURIParam],
		OwnDID:       ownDID,
		ResponseType: params[responseTypeParam],
	}
	return session
}

func idToDID(id string) did.DID {
	return did.DID{
		// should be changed to web when migrated to web DID
		Method:    "nuts",
		ID:        id,
		DecodedID: id,
	}
}
