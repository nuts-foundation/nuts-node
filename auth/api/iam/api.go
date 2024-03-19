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
	crypto2 "crypto"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	http2 "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var _ core.Routable = &Wrapper{}
var _ StrictServerInterface = &Wrapper{}

const apiPath = "iam"
const apiModuleName = auth.ModuleName + "/" + apiPath
const httpRequestContextKey = "http-request"

// accessTokenValidity defines how long access tokens are valid.
// TODO: Might want to make this configurable at some point
const accessTokenValidity = 15 * time.Minute

//go:embed assets
var assets embed.FS

// Wrapper handles OAuth2 flows.
type Wrapper struct {
	vcr           vcr.VCR
	vdr           vdr.VDR
	auth          auth.AuthenticationServices
	policyBackend policy.PDPBackend
	templates     *template.Template
	storageEngine storage.Engine
}

func New(authInstance auth.AuthenticationServices, vcrInstance vcr.VCR, vdrInstance vdr.VDR, storageEngine storage.Engine, policyBackend policy.PDPBackend) *Wrapper {
	templates := template.New("oauth2 templates")
	_, err := templates.ParseFS(assets, "assets/*.html")
	if err != nil {
		panic(err)
	}
	return &Wrapper{
		storageEngine: storageEngine,
		auth:          authInstance,
		policyBackend: policyBackend,
		vcr:           vcrInstance,
		vdr:           vdrInstance,
		templates:     templates,
	}
}

func (r Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(r, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				return r.middleware(ctx, request, operationID, f)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, apiModuleName, operationID)
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
	// The following handlers are used for the user facing OAuth2 flows.
	router.GET("/oauth2/:did/user", r.handleUserLanding, auditMiddleware)
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
		ctx.Set(core.ErrorWriterContextKey, &oauth.Oauth2ErrorWriter{})
	}

	return f(ctx, request)
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		vcrTypes.ErrNotFound: http.StatusNotFound,
	})
}

// HandleTokenRequest handles calls to the token endpoint for exchanging a grant (e.g authorization code or pre-authorized code) for an access token.
func (r Wrapper) HandleTokenRequest(ctx context.Context, request HandleTokenRequestRequestObject) (HandleTokenRequestResponseObject, error) {
	ownDID, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, err
	}
	switch request.Body.GrantType {
	case "authorization_code":
		// Options:
		// - OpenID4VCI
		// - OpenID4VP
		return r.handleAccessTokenRequest(ctx, *ownDID, request.Body.Code, request.Body.RedirectUri, request.Body.ClientId)
	case "urn:ietf:params:oauth:grant-type:pre-authorized_code":
		// Options:
		// - OpenID4VCI
		return nil, oauth.OAuth2Error{
			Code:        oauth.UnsupportedGrantType,
			Description: "not implemented yet",
		}
	case "vp_token-bearer":
		// Nuts RFC021 vp_token bearer flow
		if request.Body.PresentationSubmission == nil || request.Body.Scope == nil || request.Body.Assertion == nil {
			return nil, oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: "missing required parameters",
			}
		}
		return r.handleS2SAccessTokenRequest(ctx, *ownDID, *request.Body.Scope, *request.Body.PresentationSubmission, *request.Body.Assertion)
	default:
		return nil, oauth.OAuth2Error{
			Code:        oauth.UnsupportedGrantType,
			Description: fmt.Sprintf("grant_type '%s' is not supported", request.Body.GrantType),
		}
	}
}

func (r Wrapper) Callback(ctx context.Context, request CallbackRequestObject) (CallbackResponseObject, error) {
	// check id in path
	_, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		// this is an OAuthError already, will be rendered as 400 but that's fine (for now) for an illegal id
		return nil, err
	}

	// if error is present, delegate call to error handler
	if request.Params.Error != nil {
		return r.handleCallbackError(request)
	}

	return r.handleCallback(ctx, request)
}

func (r Wrapper) RetrieveAccessToken(_ context.Context, request RetrieveAccessTokenRequestObject) (RetrieveAccessTokenResponseObject, error) {
	// get access token from store
	var token TokenResponse
	err := r.accessTokenClientStore().Get(request.SessionID, &token)
	if err != nil {
		return nil, err
	}
	if token.Status != nil && *token.Status == oauth.AccessTokenRequestStatusPending {
		// return pending status
		return RetrieveAccessToken200JSONResponse(token), nil
	}
	// delete access token from store
	// change this when tokens can be cached
	err = r.accessTokenClientStore().Delete(request.SessionID)
	if err != nil {
		return nil, err
	}
	// return access token
	return RetrieveAccessToken200JSONResponse(token), nil
}

// IntrospectAccessToken allows the resource server (XIS/EHR) to introspect details of an access token issued by this node
func (r Wrapper) IntrospectAccessToken(_ context.Context, request IntrospectAccessTokenRequestObject) (IntrospectAccessTokenResponseObject, error) {
	// Validate token
	if request.Body.Token == "" {
		// Return 200 + 'Active = false' when token is invalid or malformed
		log.Logger().Debug("IntrospectAccessToken: missing token")
		return IntrospectAccessToken200JSONResponse{}, nil
	}

	token := AccessToken{}
	if err := r.accessTokenServerStore().Get(request.Body.Token, &token); err != nil {
		// Return 200 + 'Active = false' when token is invalid or malformed
		if errors.Is(err, storage.ErrNotFound) {
			log.Logger().Debug("IntrospectAccessToken: token not found (unknown or expired)")
			return IntrospectAccessToken200JSONResponse{}, nil
		}
		log.Logger().WithError(err).Error("IntrospectAccessToken: failed to retrieve token")
		return nil, err
	}

	if token.Expiration.Before(time.Now()) {
		// Return 200 + 'Active = false' when token is invalid or malformed
		// can happen between token expiration and pruning of database
		log.Logger().Debug("IntrospectAccessToken: token is expired")
		return IntrospectAccessToken200JSONResponse{}, nil
	}

	// Create and return introspection response
	iat := int(token.IssuedAt.Unix())
	exp := int(token.Expiration.Unix())
	response := IntrospectAccessToken200JSONResponse{
		Active:                         true,
		Iat:                            &iat,
		Exp:                            &exp,
		Iss:                            &token.Issuer,
		Sub:                            &token.Issuer,
		ClientId:                       &token.ClientId,
		Scope:                          &token.Scope,
		InputDescriptorConstraintIdMap: &token.InputDescriptorConstraintIdMap,
		PresentationDefinition:         nil,
		PresentationSubmission:         nil,
		Vps:                            &token.VPToken,

		// TODO: user authentication, used in OpenID4VP flow
		FamilyName:     nil,
		Prefix:         nil,
		Initials:       nil,
		AssuranceLevel: nil,
		Email:          nil,
		UserRole:       nil,
		Username:       nil,
	}

	// set presentation definition if in token
	var err error
	response.PresentationDefinition, err = toAnyMap(token.PresentationDefinition)
	if err != nil {
		log.Logger().WithError(err).Error("IntrospectAccessToken: failed to marshal presentation definition")
		return IntrospectAccessToken200JSONResponse{}, err
	}

	// set presentation submission if in token
	response.PresentationSubmission, err = toAnyMap(token.PresentationSubmission)
	if err != nil {
		log.Logger().WithError(err).Error("IntrospectAccessToken: failed to marshal presentation submission")
		return IntrospectAccessToken200JSONResponse{}, err
	}
	return response, nil
}

// toAnyMap marshals and unmarshals input into *map[string]any. Useful to generate OAPI response objects.
func toAnyMap(input any) (*map[string]any, error) {
	if input == nil {
		return nil, nil
	}
	bs, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	result := make(map[string]any)
	err = json.Unmarshal(bs, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// HandleAuthorizeRequest handles calls to the authorization endpoint for starting an authorization code flow.
func (r Wrapper) HandleAuthorizeRequest(ctx context.Context, request HandleAuthorizeRequestRequestObject) (HandleAuthorizeRequestResponseObject, error) {
	ownDID, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	// Workaround: deepmap codegen doesn't support dynamic query parameters.
	//             See https://github.com/deepmap/oapi-codegen/issues/1129
	httpRequest := ctx.Value(httpRequestContextKey).(*http.Request)
	params := parseQueryParams(httpRequest.URL.Query())
	clientId := params.get(oauth.ClientIDParam)

	// if the request param is present, JAR (RFC9101, JWT Authorization Request) is used
	// we parse the request and validate
	if rawToken := params.get(oauth.RequestParam); rawToken != "" {
		params, err = r.validateJARRequest(ctx, rawToken, clientId)
		if err != nil {
			return nil, err
		}
	} // else, we'll allow for now, since other flows will break if we require JAR at this point.

	// todo: store session in database? Isn't session specific for a particular flow?
	session := createSession(params, *ownDID)

	switch session.ResponseType {
	case responseTypeCode:
		// Options:
		// - Regular authorization code flow for EHR data access through access token, authentication of end-user using OpenID4VP.
		// - OpenID4VCI; authorization code flow for credential issuance to (end-user) wallet

		// TODO: officially flow switching has to be determined by the client_id
		// registered client_ids should list which flow they support
		// client registration could be done via rfc7591....
		// for now we switch on client_id format.
		// when client_id is a did:web, it is a cloud/server wallet
		// otherwise it's a normal registered client which we do not support yet
		// Note: this is the user facing OpenID4VP flow with a "vp_token" responseType, the demo uses the "vp_token id_token" responseType
		clientId := session.ClientID
		if strings.HasPrefix(clientId, "did:web:") {
			// client is a cloud wallet with user
			return r.handleAuthorizeRequestFromHolder(ctx, *ownDID, params)
		} else {
			return nil, oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: "client_id must be a did:web",
			}
		}
	case responseTypeVPToken:
		// Options:
		// - OpenID4VP flow, vp_token is sent in Authorization Response
		return r.handleAuthorizeRequestFromVerifier(ctx, *ownDID, params)
	case responseTypeVPIDToken:
		// Options:
		// - OpenID4VP+SIOP flow, vp_token is sent in Authorization Response
		return r.handlePresentationRequest(ctx, params, session)
	default:
		// TODO: This should be a redirect?
		redirectURI, _ := url.Parse(session.RedirectURI)
		return nil, oauth.OAuth2Error{
			Code:        oauth.UnsupportedResponseType,
			RedirectURI: redirectURI,
		}
	}
}

// validateJARRequest validates a JAR (JWT Authorization Request) and returns the JWT claims.
// the client_id must match the signer of the JWT.
func (r *Wrapper) validateJARRequest(ctx context.Context, rawToken string, clientId string) (oauthParameters, error) {
	var signerKid string
	// Parse and validate the JWT
	token, err := crypto.ParseJWT(rawToken, func(kid string) (crypto2.PublicKey, error) {
		signerKid = kid
		return resolver.DIDKeyResolver{Resolver: r.vdr}.ResolveKeyByID(kid, nil, resolver.AssertionMethod)
	}, jwt.WithValidate(true))
	if err != nil {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid request parameter", InternalError: err}
	}
	claimsAsMap, err := token.AsMap(ctx)
	if err != nil {
		// very unlikely
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid request parameter", InternalError: err}
	}
	params := parseJWTClaims(claimsAsMap)
	// check client_id claim, it must be the same as the client_id in the request
	if clientId != params.get(oauth.ClientIDParam) {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid client_id claim in signed authorization request"}
	}
	// check if the signer of the JWT is the client
	signer, err := did.ParseDIDURL(signerKid)
	if err != nil {
		// very unlikely since the key has already been resolved
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "invalid signer", InternalError: err}
	}
	if signer.DID.String() != clientId {
		return nil, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "client_id does not match signer of authorization request"}
	}
	return params, nil
}

// OAuthAuthorizationServerMetadata returns the Authorization Server's metadata
func (r Wrapper) OAuthAuthorizationServerMetadata(ctx context.Context, request OAuthAuthorizationServerMetadataRequestObject) (OAuthAuthorizationServerMetadataResponseObject, error) {
	ownDID, err := r.toOwnedDID(ctx, r.idToDID(request.Id).String())
	if err != nil {
		return nil, err
	}
	identity, err := didweb.DIDToURL(*ownDID)
	if err != nil {
		return nil, err
	}
	oauth2BaseURL, _ := createOAuth2EndpointURL(*ownDID) // can't fail, already did DIDToURL above
	return OAuthAuthorizationServerMetadata200JSONResponse(authorizationServerMetadata(*identity, *oauth2BaseURL)), nil
}

func (r Wrapper) GetWebDID(_ context.Context, request GetWebDIDRequestObject) (GetWebDIDResponseObject, error) {
	ownDID := r.idToDID(request.Id)
	document, err := r.vdr.ResolveManaged(ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return GetWebDID404Response{}, nil
		}
		log.Logger().WithError(err).Errorf("Could not resolve Web DID: %s", ownDID.String())
		return nil, errors.New("unable to resolve DID")
	}
	return GetWebDID200JSONResponse(*document), nil
}

// OAuthClientMetadata returns the OAuth2 Client metadata for the request.Id if it is managed by this node.
func (r Wrapper) OAuthClientMetadata(ctx context.Context, request OAuthClientMetadataRequestObject) (OAuthClientMetadataResponseObject, error) {
	ownedDID, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	identityURL, err := createOAuth2EndpointURL(*ownedDID)
	if err != nil {
		return nil, err
	}

	return OAuthClientMetadata200JSONResponse(clientMetadata(*identityURL)), nil
}
func (r Wrapper) PresentationDefinition(ctx context.Context, request PresentationDefinitionRequestObject) (PresentationDefinitionResponseObject, error) {
	if len(request.Params.Scope) == 0 {
		return PresentationDefinition200JSONResponse(PresentationDefinition{}), nil
	}

	authorizer, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	presentationDefinition, err := r.policyBackend.PresentationDefinition(ctx, *authorizer, request.Params.Scope)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidScope,
			Description: err.Error(),
		}
	}

	return PresentationDefinition200JSONResponse(*presentationDefinition), nil
}

func (r Wrapper) toOwnedDID(ctx context.Context, didAsString string) (*did.DID, error) {
	ownDID, err := did.ParseDID(didAsString)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "invalid DID: " + err.Error(),
		}
	}
	owned, err := r.vdr.IsOwner(ctx, *ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return nil, oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: "invalid issuer DID: " + err.Error(),
			}
		}
		return nil, fmt.Errorf("DID resolution failed: %w", err)
	}
	if !owned {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "issuer DID not owned by the server",
		}
	}
	return ownDID, nil
}

func (r Wrapper) RequestServiceAccessToken(ctx context.Context, request RequestServiceAccessTokenRequestObject) (RequestServiceAccessTokenResponseObject, error) {
	requestHolder, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	// resolve verifier metadata
	requestVerifier, err := did.ParseDID(request.Body.Verifier)
	if err != nil {
		return nil, core.InvalidInputError("invalid verifier: %w", err)
	}

	tokenResult, err := r.auth.IAMClient().RequestRFC021AccessToken(ctx, *requestHolder, *requestVerifier, request.Body.Scope)
	if err != nil {
		// this can be an internal server error, a 400 oauth error or a 412 precondition failed if the wallet does not contain the required credentials
		return nil, err
	}
	return RequestServiceAccessToken200JSONResponse(*tokenResult), nil
}

func (r Wrapper) RequestUserAccessToken(ctx context.Context, request RequestUserAccessTokenRequestObject) (RequestUserAccessTokenResponseObject, error) {
	requestHolder, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	if request.Body.UserId == "" {
		return nil, core.InvalidInputError("missing userID")
	}
	// require RedirectURL
	if request.Body.RedirectUri == "" {
		return nil, core.InvalidInputError("missing redirect_uri")
	}

	// session ID for calling app (supports polling for token)
	sessionID := crypto.GenerateNonce()

	// generate a redirect token valid for 5 seconds
	token := crypto.GenerateNonce()
	err = r.userRedirectStore().Put(token, RedirectSession{
		AccessTokenRequest: request,
		SessionID:          sessionID,
		OwnDID:             *requestHolder,
	})
	if err != nil {
		return nil, err
	}
	status := oauth.AccessTokenRequestStatusPending
	err = r.accessTokenClientStore().Put(sessionID, TokenResponse{
		Status: &status,
	})

	// generate a link to the redirect endpoint
	webURL, err := createOAuth2EndpointURL(*requestHolder, "user")
	if err != nil {
		return nil, err
	}
	// redirect to generic user page, context of token will render correct page
	redirectURL := http2.AddQueryParams(*webURL, map[string]string{
		"token": token,
	})
	return RequestUserAccessToken200JSONResponse{
		RedirectUri: redirectURL.String(),
		SessionId:   sessionID,
	}, nil
}

func createSession(params oauthParameters, ownDID did.DID) *OAuthSession {
	session := OAuthSession{}
	session.ClientID = params.get(oauth.ClientIDParam)
	session.Scope = params.get(oauth.ScopeParam)
	session.ClientState = params.get(oauth.StateParam)
	session.ServerState = map[string]interface{}{}
	session.RedirectURI = params.get(oauth.RedirectURIParam)
	session.OwnDID = &ownDID
	session.ResponseType = params.get(oauth.ResponseTypeParam)

	return &session
}

func (r Wrapper) StatusList(ctx context.Context, request StatusListRequestObject) (StatusListResponseObject, error) {
	requestDID, err := did.ParseDID(request.Did)
	if err != nil {
		return nil, err
	}
	cred, err := r.vcr.Issuer().StatusList(ctx, *requestDID, request.Page)
	if err != nil {
		return nil, err
	}

	return StatusList200JSONResponse(*cred), nil
}

// idToDID converts the tenant-specific part of a did:web DID (e.g. 123)
// to a fully qualified did:web DID (e.g. did:web:example.com:123), using the configured Nuts node URL.
func (r Wrapper) idToDID(id string) did.DID {
	identityURL := r.auth.PublicURL().JoinPath("iam", id)
	result, _ := didweb.URLToDID(*identityURL)
	return *result
}

// accessTokenClientStore is used by the client to store pending access tokens and return them to the calling app.
func (r Wrapper) accessTokenClientStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(accessTokenValidity, "clientaccesstoken")
}

// accessTokenServerStore is used by the Auth server to store issued access tokens
func (r Wrapper) accessTokenServerStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(accessTokenValidity, "serveraccesstoken")
}

// createOAuth2EndpointURL creates an OAuth2 endpoint URL for an owned did:web DID, for the given endpoint.
// It creates a URL in the following format: https://<did:web host>/oauth2/<did>/<endpoint>
func createOAuth2EndpointURL(webDID did.DID, endpointPath ...string) (*url.URL, error) {
	didURL, err := didweb.DIDToURL(webDID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DID to URL: %w", err)
	}
	result := new(url.URL)
	result.Scheme = didURL.Scheme
	result.Host = didURL.Host
	result.Path = path.Join("oauth2", webDID.String())
	result = result.JoinPath(endpointPath...)
	return result, nil
}
