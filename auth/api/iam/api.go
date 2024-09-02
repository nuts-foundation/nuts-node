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
	"crypto"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/http/cache"
	"github.com/nuts-foundation/nuts-node/http/user"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/api/iam/assets"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	nutsHttp "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

var _ core.Routable = &Wrapper{}
var _ StrictServerInterface = &Wrapper{}

var oauthRequestObjectKey = []string{"oauth", "requestobject"}

const apiPath = "iam"
const apiModuleName = auth.ModuleName + "/" + apiPath

type httpRequestContextKey struct{}

// accessTokenValidity defines how long access tokens are valid.
// TODO: Might want to make this configurable at some point
const accessTokenValidity = 15 * time.Minute

// cacheControlMaxAgeURLs holds API endpoints that should have a max-age cache control header set.
var cacheControlMaxAgeURLs = []string{
	"/oauth2/:subject/presentation_definition",
	"/.well-known/oauth-authorization-server/oauth2/:subject",
	"/oauth2/:subject/oauth-client",
	"/statuslist/:did/:page",
}

// cacheControlNoCacheURLs holds API endpoints that should have a no-cache cache control header set.
var cacheControlNoCacheURLs = []string{
	"/oauth2/:subject/token",
}

type TokenIntrospectionResponse = ExtendedTokenIntrospectionResponse

//go:embed assets
var assetsFS embed.FS

// Wrapper handles OAuth2 flows.
type Wrapper struct {
	auth           auth.AuthenticationServices
	policyBackend  policy.PDPBackend
	storageEngine  storage.Engine
	jsonldManager  jsonld.JSONLD
	vcr            vcr.VCR
	vdr            vdr.VDR
	jwtSigner      nutsCrypto.JWTSigner
	keyResolver    resolver.KeyResolver
	subjectManager didsubject.SubjectManager
	_jar           atomic.Value
}

func New(
	authInstance auth.AuthenticationServices, vcrInstance vcr.VCR, vdrInstance vdr.VDR, subjectManager didsubject.SubjectManager, storageEngine storage.Engine,
	policyBackend policy.PDPBackend, jwtSigner nutsCrypto.JWTSigner, jsonldManager jsonld.JSONLD) *Wrapper {

	templates := template.New("oauth2 templates")
	_, err := templates.ParseFS(assetsFS, "assets/*.html")
	if err != nil {
		panic(err)
	}
	keyResolver := resolver.DIDKeyResolver{Resolver: vdrInstance.Resolver()}
	return &Wrapper{
		auth:           authInstance,
		policyBackend:  policyBackend,
		storageEngine:  storageEngine,
		vcr:            vcrInstance,
		vdr:            vdrInstance,
		subjectManager: subjectManager,
		jsonldManager:  jsonldManager,
		jwtSigner:      jwtSigner,
		keyResolver:    keyResolver,
	}
}

func (r Wrapper) jar() JAR {
	// so we can mock it in tests
	var current JAR
	var ok bool
	if current, ok = r._jar.Load().(JAR); !ok {
		current = NewJAR(r.auth, r.jwtSigner, r.keyResolver, r.auth.IAMClient())
		r._jar.Store(current)
	}
	return current
}

func (r Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(r, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				return r.strictMiddleware(ctx, request, operationID, f)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, apiModuleName, operationID)
		},
	}))
	// The following handlers are used for the user facing OAuth2 flows.
	router.GET("/oauth2/:subjectID/user", r.handleUserLanding, func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			middleware(c, "handleUserLanding")
			return next(c)
		}
	}, audit.Middleware(apiModuleName))
	router.Use(cache.MaxAge(5*time.Minute, cacheControlMaxAgeURLs...).Handle)
	router.Use(cache.NoCache(cacheControlNoCacheURLs...).Handle)
	router.Use(user.SessionMiddleware{
		Skipper: func(c echo.Context) bool {
			// The following URLs require a user session:
			paths := []string{
				"/oauth2/:subjectID/user",
				"/oauth2/:subjectID/authorize",
				"/oauth2/:subjectID/callback",
			}
			for _, path := range paths {
				if c.Path() == path {
					return false
				}
			}
			return true
		},
		TimeOut: time.Hour,
		Store:   r.storageEngine.GetSessionDatabase().GetStore(time.Hour, "user", "session"),
		CookiePath: func(subjectID string) string {
			baseURL := r.subjectToBaseURL(subjectID)
			return baseURL.Path
		},
	}.Handle)
}

func (r Wrapper) strictMiddleware(ctx echo.Context, request interface{}, operationID string, f StrictHandlerFunc) (interface{}, error) {
	middleware(ctx, operationID)
	return f(ctx, request)
}

func middleware(ctx echo.Context, operationID string) {
	ctx.Set(core.OperationIDContextKey, operationID)
	ctx.Set(core.ModuleNameContextKey, apiModuleName)

	// Add http.Request to context, to allow reading URL query parameters
	requestCtx := context.WithValue(ctx.Request().Context(), httpRequestContextKey{}, ctx.Request())
	ctx.SetRequest(ctx.Request().WithContext(requestCtx))
	if strings.HasPrefix(ctx.Request().URL.Path, "/oauth2/") {
		ctx.Set(core.ErrorWriterContextKey, &oauth.Oauth2ErrorWriter{
			HtmlPageTemplate: assets.ErrorTemplate,
		})
	}
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (r Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		vcrTypes.ErrNotFound:                http.StatusNotFound,
		resolver.ErrDIDNotManagedByThisNode: http.StatusBadRequest,
		holder.ErrNoCredentials:             http.StatusPreconditionFailed,
		didsubject.ErrSubjectNotFound:       http.StatusNotFound,
	})
}

// HandleTokenRequest handles calls to the token endpoint for exchanging a grant (e.g authorization code or pre-authorized code) for an access token.
func (r Wrapper) HandleTokenRequest(ctx context.Context, request HandleTokenRequestRequestObject) (HandleTokenRequestResponseObject, error) {
	err := r.subjectExists(ctx, request.Subject)
	if err != nil {
		return nil, err
	}
	switch request.Body.GrantType {
	case oauth.AuthorizationCodeGrantType:
		// Options:
		// - OpenID4VCI
		// - OpenID4VP
		// verifier DID is taken from code->oauthSession storage
		return r.handleAccessTokenRequest(ctx, *request.Body)
	case oauth.PreAuthorizedCodeGrantType:
		// Options:
		// - OpenID4VCI
		// todo: add to grantTypesSupported in AS metadata once supported
		return nil, oauth.OAuth2Error{
			Code:        oauth.UnsupportedGrantType,
			Description: "not implemented yet",
		}
	case oauth.VpTokenGrantType:
		// Nuts RFC021 vp_token bearer flow
		if request.Body.PresentationSubmission == nil || request.Body.Scope == nil || request.Body.Assertion == nil {
			return nil, oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: "missing required parameters",
			}
		}
		return r.handleS2SAccessTokenRequest(ctx, request.Subject, *request.Body.Scope, *request.Body.PresentationSubmission, *request.Body.Assertion)
	default:
		return nil, oauth.OAuth2Error{
			Code:        oauth.UnsupportedGrantType,
			Description: fmt.Sprintf("grant_type '%s' is not supported", request.Body.GrantType),
		}
	}
}

func (r Wrapper) Callback(ctx context.Context, request CallbackRequestObject) (CallbackResponseObject, error) {
	if !r.auth.AuthorizationEndpointEnabled() {
		// Callback endpoint is only used by flows initiated through the authorization endpoint.
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "callback endpoint is disabled",
		}
	}
	// validate request
	// check did in path
	err := r.subjectExists(ctx, request.SubjectID)
	if err != nil {
		return nil, err
	}
	// check if state is present and resolves to a client state
	if request.Params.State == nil || *request.Params.State == "" {
		// without state it is an invalid request, but try to provide as much useful information as possible
		if request.Params.Error != nil && *request.Params.Error != "" {
			callbackError := callbackRequestToError(request, nil)
			callbackError.InternalError = errors.New("missing state parameter")
			return nil, callbackError
		}
		return nil, oauthError(oauth.InvalidRequest, "missing state parameter")
	}
	oauthSession := new(OAuthSession)
	if err = r.oauthClientStateStore().Get(*request.Params.State, oauthSession); err != nil {
		return nil, oauthError(oauth.InvalidRequest, "invalid or expired state", err)
	}
	if request.SubjectID != *oauthSession.OwnSubject {
		// TODO: this is a manipulated request, add error logging?
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "session subject does not match request"), oauthSession.redirectURI())
	}

	// if error is present, redirect error back to application initiating the flow
	if request.Params.Error != nil && *request.Params.Error != "" {
		return nil, callbackRequestToError(request, oauthSession.redirectURI())
	}

	// check if code is present
	if request.Params.Code == nil || *request.Params.Code == "" {
		return nil, withCallbackURI(oauthError(oauth.InvalidRequest, "missing code parameter"), oauthSession.redirectURI())
	}

	// continue flow
	switch oauthSession.ClientFlow {
	case credentialRequestClientFlow:
		return r.handleOpenID4VCICallback(ctx, *request.Params.Code, oauthSession)
	case accessTokenRequestClientFlow:
		return r.handleCallback(ctx, *request.Params.Code, oauthSession)
	default:
		// programming error, should never happen
		return nil, withCallbackURI(oauthError(oauth.ServerError, "unknown client flow for callback: '"+oauthSession.ClientFlow+"'"), oauthSession.redirectURI())
	}
}

// callbackRequestToError should only be used if request.params.Error is present
func callbackRequestToError(request CallbackRequestObject, redirectURI *url.URL) oauth.OAuth2Error {
	requestErr := oauth.OAuth2Error{
		Code:        oauth.ErrorCode(*request.Params.Error),
		RedirectURI: redirectURI,
	}
	if request.Params.ErrorDescription != nil {
		requestErr.Description = *request.Params.ErrorDescription
	}
	return requestErr
}

func (r Wrapper) RetrieveAccessToken(_ context.Context, request RetrieveAccessTokenRequestObject) (RetrieveAccessTokenResponseObject, error) {
	// get access token from store
	var token TokenResponse
	err := r.accessTokenClientStore().Get(request.SessionID, &token)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, core.NotFoundError("session not found")
		}
		return nil, err
	}
	if token.Get("status") == oauth.AccessTokenRequestStatusPending {
		// return pending status
		return RetrieveAccessToken200JSONResponse(token), nil
	}
	// access token is active, return to caller and delete access token from store
	// change this when tokens can be cached
	err = r.accessTokenClientStore().Delete(request.SessionID)
	if err != nil {
		log.Logger().WithError(err).Warn("Failed to delete access token")
	}
	// return access token
	return RetrieveAccessToken200JSONResponse(token), nil
}

// IntrospectAccessToken allows the resource server (XIS/EHR) to introspect details of an access token issued by this node
func (r Wrapper) IntrospectAccessToken(_ context.Context, request IntrospectAccessTokenRequestObject) (IntrospectAccessTokenResponseObject, error) {
	input := request.Body.Token
	response, err := r.introspectAccessToken(input)
	if err != nil {
		return nil, err
	} else if response == nil {
		return IntrospectAccessToken200JSONResponse{}, nil
	}
	response.Vps = nil
	response.PresentationDefinitions = nil
	response.PresentationSubmissions = nil
	return IntrospectAccessToken200JSONResponse(*response), nil
}

// IntrospectAccessTokenExtended allows the resource server (XIS/EHR) to introspect details of an access token issued by this node.
// It returns the same information as IntrospectAccessToken, but with additional information.
func (r Wrapper) IntrospectAccessTokenExtended(_ context.Context, request IntrospectAccessTokenExtendedRequestObject) (IntrospectAccessTokenExtendedResponseObject, error) {
	input := request.Body.Token
	response, err := r.introspectAccessToken(input)
	if err != nil {
		return nil, err
	} else if response == nil {
		return IntrospectAccessTokenExtended200JSONResponse{}, nil
	}
	return IntrospectAccessTokenExtended200JSONResponse(*response), nil
}

func (r Wrapper) introspectAccessToken(input string) (*ExtendedTokenIntrospectionResponse, error) {
	// Validate token
	if input == "" {
		// Return 200 + 'Active = false' when token is invalid or malformed
		log.Logger().Debug("IntrospectAccessToken: missing token")
		return nil, nil
	}

	token := AccessToken{}
	if err := r.accessTokenServerStore().Get(input, &token); err != nil {
		// Return 200 + 'Active = false' when token is invalid or malformed
		if errors.Is(err, storage.ErrNotFound) {
			log.Logger().Debug("IntrospectAccessToken: token not found (unknown or expired)")
			return nil, nil
		}
		log.Logger().WithError(err).Error("IntrospectAccessToken: failed to retrieve token")
		return nil, err
	}

	if token.Expiration.Before(time.Now()) {
		// Return 200 + 'Active = false' when token is invalid or malformed
		// can happen between token expiration and pruning of database
		log.Logger().Debug("IntrospectAccessToken: token is expired")
		return nil, nil
	}

	// Optional:
	// Use DPoP from token to generate JWK thumbprint for public key
	// deserialization of the DPoP struct from the accessTokenServerStore triggers validation of the DPoP header
	// SHA256 hashing won't fail.
	var cnf *Cnf
	if token.DPoP != nil {
		hash, _ := token.DPoP.Headers.JWK().Thumbprint(crypto.SHA256)
		base64Hash := base64.RawURLEncoding.EncodeToString(hash)
		cnf = &Cnf{Jkt: base64Hash}
	}

	// Create and return introspection response
	iat := int(token.IssuedAt.Unix())
	exp := int(token.Expiration.Unix())
	response := ExtendedTokenIntrospectionResponse{
		Active:                  true,
		Cnf:                     cnf,
		Iat:                     &iat,
		Exp:                     &exp,
		Iss:                     &token.Issuer,
		Sub:                     &token.Issuer,
		ClientId:                &token.ClientId,
		Scope:                   &token.Scope,
		Vps:                     &token.VPToken,
		PresentationDefinitions: &token.PresentationDefinitions,
		PresentationSubmissions: &token.PresentationSubmissions,
	}

	if token.InputDescriptorConstraintIdMap != nil {
		for _, reserved := range []string{"iss", "sub", "exp", "iat", "active", "client_id", "scope"} {
			if _, isReserved := token.InputDescriptorConstraintIdMap[reserved]; isReserved {
				return nil, fmt.Errorf("IntrospectAccessToken: InputDescriptorConstraintIdMap contains reserved claim name: %s", reserved)
			}
		}
		response.AdditionalProperties = token.InputDescriptorConstraintIdMap
	}
	return &response, nil
}

// HandleAuthorizeRequest handles calls to the authorization endpoint for starting an authorization code flow.
func (r Wrapper) HandleAuthorizeRequest(ctx context.Context, request HandleAuthorizeRequestRequestObject) (HandleAuthorizeRequestResponseObject, error) {
	if !r.auth.AuthorizationEndpointEnabled() {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "authorization endpoint is disabled",
		}
	}
	err := r.subjectExists(ctx, request.SubjectID)
	if err != nil {
		return nil, err
	}
	clientID := r.subjectToBaseURL(request.SubjectID)
	metadata, err := r.oauthAuthorizationServerMetadata(clientID)
	if err != nil {
		return nil, err
	}

	// Workaround: deepmap codegen doesn't support dynamic query parameters.
	//             See https://github.com/deepmap/oapi-codegen/issues/1129
	httpRequest := ctx.Value(httpRequestContextKey{}).(*http.Request)
	return r.handleAuthorizeRequest(ctx, request.SubjectID, *metadata, *httpRequest.URL)
}

// handleAuthorizeRequest handles calls to the authorization endpoint for starting an authorization code flow.
// The caller must ensure ownDID is actually owned by this node.
func (r Wrapper) handleAuthorizeRequest(ctx context.Context, subject string, ownMetadata oauth.AuthorizationServerMetadata, request url.URL) (HandleAuthorizeRequestResponseObject, error) {
	// parse and validate as JAR (RFC9101, JWT Authorization Request)
	requestObject, err := r.jar().Parse(ctx, ownMetadata, request.Query())
	if err != nil {
		// already an oauth.OAuth2Error
		return nil, err
	}

	switch requestObject.get(oauth.ResponseTypeParam) {
	case oauth.CodeResponseType:
		// Options:
		// - Regular authorization code flow for EHR data access through access token, authentication of end-user using OpenID4VP.
		// - OpenID4VCI; authorization code flow for credential issuance to (end-user) wallet

		// TODO: officially flow switching has to be determined by the client_id
		// registered client_ids should list which flow they support
		// client registration could be done via rfc7591....
		// if client_id is a url, we can use OpenID federation for automatic client registration
		return r.handleAuthorizeRequestFromHolder(ctx, subject, requestObject)
	case oauth.VPTokenResponseType:
		// Options:
		// - OpenID4VP flow, vp_token is sent in Authorization Response
		// non-spec: if the scheme is openid4vp (URL starts with openid4vp:), the OpenID4VP request should be handled by a user wallet, rather than an organization wallet.
		//           Requests to user wallets can then be rendered as QR-code (or use a cloud wallet).
		//           Note that it can't be called from the outside, but only by internal dispatch (since Echo doesn't handle openid4vp:, obviously).
		walletOwnerType := pe.WalletOwnerOrganization
		if strings.HasPrefix(request.String(), "openid4vp:") {
			walletOwnerType = pe.WalletOwnerUser
		}
		return r.handleAuthorizeRequestFromVerifier(ctx, subject, requestObject, walletOwnerType)
	default:
		// TODO: This should be a redirect?
		redirectURI, _ := url.Parse(requestObject.get(oauth.RedirectURIParam))
		return nil, oauth.OAuth2Error{
			Code:        oauth.UnsupportedResponseType,
			RedirectURI: redirectURI,
		}
	}
}

// RequestJWTByGet returns the Request Object referenced as 'request_uri' in an authorization request.
// RFC9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR).
func (r Wrapper) RequestJWTByGet(ctx context.Context, request RequestJWTByGetRequestObject) (RequestJWTByGetResponseObject, error) {
	ro := new(jarRequest)
	err := r.authzRequestObjectStore().GetAndDelete(request.Id, ro)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "request object not found",
		}
	}
	expected := r.subjectToBaseURL(request.Subject)
	if ro.Client != expected.String() {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "client_id does not match request",
		}
	}
	if ro.RequestURIMethod != "get" { // case sensitive
		// TODO: wallet does not support `request_uri_method=post`. Spec is unclear if this should fail, or fallback to using staticAuthorizationServerMetadata().
		return nil, oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			Description:   "used request_uri_method 'get' on a 'post' request_uri",
			InternalError: errors.New("wrong 'request_uri_method' authorization server or wallet probably does not support 'request_uri_method'"),
		}
	}

	// TODO: supported signature types should be checked
	token, err := r.jar().Sign(ctx, ro.Claims)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "unable to create Request Object",
			InternalError: fmt.Errorf("failed to sign authorization Request Object: %w", err),
		}
	}
	return RequestJWTByGet200ApplicationoauthAuthzReqJwtResponse{
		Body:          bytes.NewReader([]byte(token)),
		ContentLength: int64(len(token)),
	}, nil
}

// RequestJWTByPost returns the Request Object referenced as 'request_uri' in an authorization request.
// Extension of OpenID 4 Verifiable Presentations (OpenID4VP) on
// RFC9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR).
func (r Wrapper) RequestJWTByPost(ctx context.Context, request RequestJWTByPostRequestObject) (RequestJWTByPostResponseObject, error) {
	ro := new(jarRequest)
	err := r.authzRequestObjectStore().GetAndDelete(request.Id, ro)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "request object not found",
		}
	}
	expected := r.subjectToBaseURL(request.Subject)
	if ro.Client != expected.String() {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "client_id does not match request",
		}
	}
	if ro.RequestURIMethod != "post" { // case sensitive
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "used request_uri_method 'post' on a 'get' request_uri",
		}
	}

	walletMetadata := staticAuthorizationServerMetadata()
	if request.Body != nil {
		if request.Body.WalletMetadata != nil {
			walletMetadata = *request.Body.WalletMetadata
		}
		if request.Body.WalletNonce != nil {
			ro.Claims[oauth.WalletNonceParam] = *request.Body.WalletNonce
		}
	}
	if walletMetadata.Issuer != "https://self-issued.me/v2" {
		ro.Claims[jwt.AudienceKey] = walletMetadata.Issuer
	}

	// TODO: supported signature types should be checked
	token, err := r.jar().Sign(ctx, ro.Claims)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "unable to create Request Object",
			InternalError: fmt.Errorf("failed to sign authorization Request Object: %w", err),
		}
	}
	return RequestJWTByPost200ApplicationoauthAuthzReqJwtResponse{
		Body:          bytes.NewReader([]byte(token)),
		ContentLength: int64(len(token)),
	}, nil
}

// OAuthAuthorizationServerMetadata returns the Authorization Server's metadata
func (r Wrapper) OAuthAuthorizationServerMetadata(_ context.Context, request OAuthAuthorizationServerMetadataRequestObject) (OAuthAuthorizationServerMetadataResponseObject, error) {
	clientID := r.subjectToBaseURL(request.Subject)
	md, err := r.oauthAuthorizationServerMetadata(clientID)
	if err != nil {
		return nil, err
	}
	return OAuthAuthorizationServerMetadata200JSONResponse(*md), nil
}

func (r Wrapper) oauthAuthorizationServerMetadata(clientID url.URL) (*oauth.AuthorizationServerMetadata, error) {
	md := authorizationServerMetadata(clientID, r.vdr.SupportedMethods())
	if !r.auth.AuthorizationEndpointEnabled() {
		md.AuthorizationEndpoint = ""
	}
	return &md, nil
}

// OAuthClientMetadata returns the OAuth2 Client metadata for the request.Id if it is managed by this node.
func (r Wrapper) OAuthClientMetadata(ctx context.Context, request OAuthClientMetadataRequestObject) (OAuthClientMetadataResponseObject, error) {
	err := r.subjectExists(ctx, request.Subject)
	if err != nil {
		return nil, err
	}

	identityURL := r.subjectToBaseURL(request.Subject)

	return OAuthClientMetadata200JSONResponse(clientMetadata(identityURL)), nil
}

func (r Wrapper) OpenIDConfiguration(ctx context.Context, request OpenIDConfigurationRequestObject) (OpenIDConfigurationResponseObject, error) {
	// find subject
	exists, err := r.subjectManager.Exists(ctx, request.Subject)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "internal server error", // security reasons
			InternalError: err,
		}
	}
	if !exists {
		return nil, oauth.OAuth2Error{
			Code:        "not_found",
			Description: "subject not found",
		}
	}
	// find DIDs for subject
	dids, err := r.subjectManager.List(ctx, request.Subject)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "internal server error", // security reasons
			InternalError: err,
		}
	}
	// resolve DID keys
	set := jwk.NewSet()
	var signingKey string
	for _, did := range dids {
		kid, key, err := r.keyResolver.ResolveKey(did, nil, resolver.AssertionMethod)
		if err != nil {
			return nil, oauth.OAuth2Error{
				Code:          oauth.ServerError,
				Description:   "internal server error", // security reasons
				InternalError: err,
			}
		}
		// create JWK and add to set
		jwkKey, err := jwk.FromRaw(key)
		if err != nil {
			return nil, oauth.OAuth2Error{
				Code:          oauth.ServerError,
				Description:   "internal server error", // security reasons
				InternalError: err,
			}
		}
		_ = jwkKey.Set(jwk.KeyIDKey, kid)
		_ = set.AddKey(jwkKey)
		signingKey = kid
	}
	// we sign with a JWK, the receiving party can verify with the signature but not if the key corresponds to the DID since the DID method might not be supported.
	// this is a shortcoming of the openID federation vs OpenID4VP/DID worlds
	// issuer URL equals server baseURL + :/oauth2/:subject
	baseURL := r.auth.PublicURL()
	if baseURL == nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.ServerError,
			Description: "misconfiguration: missing public URL",
		}
	}
	issuerURL, err := baseURL.Parse("/oauth2/" + request.Subject)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "internal server error",
			InternalError: err,
		}
	}
	configuration := openIDConfiguration(*issuerURL, set, r.vdr.SupportedMethods())
	claims := make(map[string]interface{})
	asJson, _ := json.Marshal(configuration)
	_ = json.Unmarshal(asJson, &claims)
	// create jwt
	token, err := r.jwtSigner.SignJWT(ctx, claims, nil, signingKey)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:          oauth.ServerError,
			Description:   "internal server error",
			InternalError: err,
		}
	}

	return OpenIDConfiguration200ApplicationentityStatementJwtResponse{
		Body:          strings.NewReader(token),
		ContentLength: int64(len(token)),
	}, nil
}

func (r Wrapper) PresentationDefinition(ctx context.Context, request PresentationDefinitionRequestObject) (PresentationDefinitionResponseObject, error) {
	if len(request.Params.Scope) == 0 {
		return PresentationDefinition200JSONResponse(PresentationDefinition{}), nil
	}

	mapping, err := r.policyBackend.PresentationDefinitions(ctx, request.Params.Scope)
	if err != nil {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidScope,
			Description: err.Error(),
		}
	}

	walletOwnerType := pe.WalletOwnerOrganization
	if request.Params.WalletOwnerType != nil {
		walletOwnerType = *request.Params.WalletOwnerType
	}
	result, exists := mapping[walletOwnerType]
	if !exists {
		return nil, oauthError(oauth.InvalidRequest, fmt.Sprintf("no presentation definition found for '%s' wallet", walletOwnerType))
	}

	return PresentationDefinition200JSONResponse(result), nil
}

func (r Wrapper) toOwnedDID(ctx context.Context, didAsString string) (*did.DID, error) {
	ownDID, err := did.ParseDID(didAsString)
	if err != nil {
		return nil, fmt.Errorf("invalid DID: %s", err)
	}
	owned, err := r.vdr.DocumentOwner().IsOwner(ctx, *ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return nil, fmt.Errorf("invalid issuer DID: %s", err)
		}
		return nil, fmt.Errorf("DID resolution failed: %w", err)
	}
	if !owned {
		return nil, resolver.ErrDIDNotManagedByThisNode
	}
	return ownDID, nil
}

func (r Wrapper) RequestServiceAccessToken(ctx context.Context, request RequestServiceAccessTokenRequestObject) (RequestServiceAccessTokenResponseObject, error) {
	err := r.subjectExists(ctx, request.Subject)
	if err != nil {
		return nil, err
	}

	var credentials []VerifiableCredential
	if request.Body.Credentials != nil {
		credentials = *request.Body.Credentials
	}

	useDPoP := true
	if request.Body.TokenType != nil && strings.EqualFold(string(*request.Body.TokenType), AccessTokenTypeBearer) {
		useDPoP = false
	}
	tokenResult, err := r.auth.IAMClient().RequestRFC021AccessToken(ctx, request.Subject, request.Body.AuthorizationServer, request.Body.Scope, useDPoP, credentials)
	if err != nil {
		// this can be an internal server error, a 400 oauth error or a 412 precondition failed if the wallet does not contain the required credentials
		return nil, err
	}
	return RequestServiceAccessToken200JSONResponse(*tokenResult), nil
}

func (r Wrapper) RequestUserAccessToken(ctx context.Context, request RequestUserAccessTokenRequestObject) (RequestUserAccessTokenResponseObject, error) {
	err := r.subjectExists(ctx, request.Subject)
	if err != nil {
		return nil, err
	}

	// Note: When we support authentication at an external IdP,
	//       the properties below become conditionally required.
	if request.Body.PreauthorizedUser == nil {
		return nil, core.InvalidInputError("missing preauthorized_user")
	}
	if request.Body.PreauthorizedUser.Id == "" {
		return nil, core.InvalidInputError("missing preauthorized_user.id")
	}
	if request.Body.PreauthorizedUser.Name == "" {
		return nil, core.InvalidInputError("missing preauthorized_user.name")
	}
	if request.Body.PreauthorizedUser.Role == "" {
		return nil, core.InvalidInputError("missing preauthorized_user.role")
	}

	if request.Body.RedirectUri == "" {
		return nil, core.InvalidInputError("missing redirect_uri")
	}

	// session ID for calling app (supports polling for token)
	sessionID := nutsCrypto.GenerateNonce()

	// generate a redirect token valid for 5 seconds
	token := nutsCrypto.GenerateNonce()
	err = r.userRedirectStore().Put(token, RedirectSession{
		AccessTokenRequest: request,
		SessionID:          sessionID,
		SubjectID:          request.Subject,
	})
	if err != nil {
		return nil, err
	}
	tokenResponse := (&TokenResponse{}).With("status", oauth.AccessTokenRequestStatusPending)
	if err = r.accessTokenClientStore().Put(sessionID, tokenResponse); err != nil {
		return nil, err
	}

	// redirect to generic user page, context of token will render correct page
	redirectURL := nutsHttp.AddQueryParams(*r.auth.PublicURL().JoinPath("oauth2", request.Subject, "user"), map[string]string{
		"token": token,
	})
	return RequestUserAccessToken200JSONResponse{
		RedirectUri: redirectURL.String(),
		SessionId:   sessionID,
	}, nil
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

func (r Wrapper) openid4vciMetadata(ctx context.Context, issuer string) (*oauth.OpenIDCredentialIssuerMetadata, *oauth.AuthorizationServerMetadata, error) {
	credentialIssuerMetadata, err := r.auth.IAMClient().OpenIdCredentialIssuerMetadata(ctx, issuer)
	if err != nil {
		return nil, nil, err
	}

	// OpenID4VCI allows multiple AuthorizationServers in credentialIssuerMetadata for a single issuer. (allows delegating issuance per VC type)
	// TODO: smart select the correct authorization server based on the metadata
	//		 https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
	// For now we just accept the first successful result, and lookup the metadata.
	var ASMetadata *oauth.AuthorizationServerMetadata
	for _, serverURL := range credentialIssuerMetadata.AuthorizationServers {
		ASMetadata, err = r.auth.IAMClient().AuthorizationServerMetadata(ctx, serverURL)
		if err == nil {
			break
		}
	}
	if ASMetadata == nil {
		// authorization_servers is an optional field. When no authorization servers are listed, the oauth Issuer is the authorization server.
		// also try issuer in case all others fail
		ASMetadata, err = r.auth.IAMClient().AuthorizationServerMetadata(ctx, issuer)
		if err != nil {
			return nil, nil, err
		}
	}
	return credentialIssuerMetadata, ASMetadata, nil
}

// createAuthorizationRequest creates an OAuth2.0 authorizationRequest redirect URL that redirects to the authorization server.
// It can create both regular OAuth2 requests and OpenID4VP requests due to the requestObjectModifier.
// This modifier is used by JAR.Create to generate a (JAR) request object that is added as 'request_uri' parameter.
// It's able to create an unsigned request and a signed request (JAR) based on the OAuth Server Metadata.
func (r Wrapper) createAuthorizationRequest(ctx context.Context, subject string, metadata oauth.AuthorizationServerMetadata, modifier requestObjectModifier) (*url.URL, error) {
	if len(metadata.AuthorizationEndpoint) == 0 {
		return nil, fmt.Errorf("no authorization endpoint found in metadata for %s", metadata.Issuer)
	}

	endpoint, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization endpoint URL: %w", err)
	}

	clientID := r.subjectToBaseURL(subject)
	clientDID, err := r.determineClientDID(ctx, metadata, subject)
	if err != nil {
		return nil, err
	}

	audience := metadata.Issuer
	if metadata.Issuer == "https://self-issued.me/v2" {
		audience = ""
	}

	// request_uri
	requestURIID := nutsCrypto.GenerateNonce()
	requestObj := r.jar().Create(*clientDID, clientID.String(), audience, modifier)
	if err := r.authzRequestObjectStore().Put(requestURIID, requestObj); err != nil {
		return nil, err
	}

	requestURI := clientID.JoinPath("request.jwt", requestURIID)

	// JAR request
	params := map[string]string{
		oauth.ClientIDParam:         clientID.String(),
		oauth.RequestURIMethodParam: requestObj.RequestURIMethod,
		oauth.RequestURIParam:       requestURI.String(),
	}
	if metadata.RequireSignedRequestObject {
		redirectURL := nutsHttp.AddQueryParams(*endpoint, params)
		return &redirectURL, nil
	}
	// else; unclear if AS has support for RFC9101, so also add all modifiers to the query itself
	// left here for completeness, node 2 node interaction always uses JAR since the AS metadata has it hardcoded
	// TODO: in the user flow we have no AS metadata, meaning that we add all params to the query.
	//         This is most likely going to fail on mobile devices due to request url length.
	modifier(params)
	redirectURL := nutsHttp.AddQueryParams(*endpoint, params)
	return &redirectURL, nil
}

// accessTokenClientStore is used by the client to store pending access tokens and return them to the calling app.
func (r Wrapper) accessTokenClientStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(accessTokenValidity, "clientaccesstoken")
}

// accessTokenServerStore is used by the Auth server to store issued access tokens
func (r Wrapper) accessTokenServerStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(accessTokenValidity, "serveraccesstoken")
}

// accessTokenServerStore is used by the Auth server to store issued access tokens
func (r Wrapper) authzRequestObjectStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(accessTokenValidity, oauthRequestObjectKey...)
}

func (r Wrapper) subjectToBaseURL(subject string) url.URL {
	u := &url.URL{}
	publicURL := r.auth.PublicURL()
	if publicURL != nil {
		u = publicURL.JoinPath("oauth2", subject)
	}
	return *u
}

// subjectExists checks whether the given subject is known on the local node.
func (r Wrapper) subjectExists(ctx context.Context, subjectID string) error {
	exists, err := r.subjectManager.Exists(ctx, subjectID)
	if err != nil {
		return err
	}
	if !exists {
		return didsubject.ErrSubjectNotFound
	}
	return nil
}

// subjectExists checks whether the given subject is known on the local node.
func (r Wrapper) subjectOwns(ctx context.Context, subjectID string, subjectDID did.DID) (bool, error) {
	dids, err := r.subjectManager.List(ctx, subjectID)
	if err != nil {
		return false, err
	}
	for _, d := range dids {
		if d.Equals(subjectDID) {
			return true, nil
		}
	}
	return false, nil
}

// todo select did method, and not the scheme
func (r Wrapper) determineClientDID(ctx context.Context, authServerMetadata oauth.AuthorizationServerMetadata, subjectID string) (*did.DID, error) {
	if !authServerMetadata.SupportsClientIDScheme(entityClientIDScheme) {
		return nil, oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "authorization server does not support 'entity' client_id scheme",
		}
	}
	candidateDIDs, err := r.subjectManager.List(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	return &candidateDIDs[0], nil
}
