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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/api/iam/assets"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	cryptoNuts "github.com/nuts-foundation/nuts-node/crypto"
	httpNuts "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

var _ core.Routable = &Wrapper{}
var _ StrictServerInterface = &Wrapper{}

var oauthRequestObjectKey = []string{"oauth", "requestobject"}

const apiPath = "iam"
const apiModuleName = auth.ModuleName + "/" + apiPath
const httpRequestContextKey = "http-request"

// accessTokenValidity defines how long access tokens are valid.
// TODO: Might want to make this configurable at some point
const accessTokenValidity = 15 * time.Minute

const oid4vciSessionValidity = 15 * time.Minute

// userSessionCookieName is the name of the cookie used to store the user session.
// It uses the __Host prefix, that instructs the user agent to treat it as a secure cookie:
// - Must be set with the Secure attribute
// - Must be set from an HTTPS uri
// - Must not contain a Domain attribute
// - Must contain a Path attribute
// Also see:
// - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes
// - https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
const userSessionCookieName = "__Host-SID"

//go:embed assets
var assetsFS embed.FS

// Wrapper handles OAuth2 flows.
type Wrapper struct {
	auth          auth.AuthenticationServices
	policyBackend policy.PDPBackend
	storageEngine storage.Engine
	keyStore      cryptoNuts.KeyStore
	vcr           vcr.VCR
	vdr           vdr.VDR
	jwtSigner     cryptoNuts.JWTSigner
	keyResolver   resolver.KeyResolver
	jar           JAR
}

func New(authInstance auth.AuthenticationServices, vcrInstance vcr.VCR, vdrInstance vdr.VDR, storageEngine storage.Engine, policyBackend policy.PDPBackend, jwtSigner cryptoNuts.JWTSigner) *Wrapper {
	templates := template.New("oauth2 templates")
	_, err := templates.ParseFS(assetsFS, "assets/*.html")
	if err != nil {
		panic(err)
	}
	return &Wrapper{
		auth:          authInstance,
		policyBackend: policyBackend,
		storageEngine: storageEngine,
		vcr:           vcrInstance,
		vdr:           vdrInstance,
		jwtSigner:     jwtSigner,
		keyResolver:   resolver.DIDKeyResolver{Resolver: vdrInstance.Resolver()},
		jar: &jar{
			auth:        authInstance,
			jwtSigner:   jwtSigner,
			keyResolver: resolver.DIDKeyResolver{Resolver: vdrInstance.Resolver()},
		},
	}
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
	router.GET("/oauth2/:did/user", r.handleUserLanding, func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			middleware(c, "handleUserLanding")
			return next(c)
		}
	}, audit.Middleware(apiModuleName))
}

func (r Wrapper) strictMiddleware(ctx echo.Context, request interface{}, operationID string, f StrictHandlerFunc) (interface{}, error) {
	middleware(ctx, operationID)
	return f(ctx, request)
}

func middleware(ctx echo.Context, operationID string) {
	ctx.Set(core.OperationIDContextKey, operationID)
	ctx.Set(core.ModuleNameContextKey, apiModuleName)

	// Add http.Request to context, to allow reading URL query parameters
	requestCtx := context.WithValue(ctx.Request().Context(), httpRequestContextKey, ctx.Request())
	ctx.SetRequest(ctx.Request().WithContext(requestCtx))
	if strings.HasPrefix(ctx.Request().URL.Path, "/oauth2/") {
		ctx.Set(core.ErrorWriterContextKey, &oauth.Oauth2ErrorWriter{
			HtmlPageTemplate: assets.ErrorTemplate,
		})
	}
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		vcrTypes.ErrNotFound:                http.StatusNotFound,
		resolver.ErrDIDNotManagedByThisNode: http.StatusBadRequest,
	})
}

// HandleTokenRequest handles calls to the token endpoint for exchanging a grant (e.g authorization code or pre-authorized code) for an access token.
func (r Wrapper) HandleTokenRequest(ctx context.Context, request HandleTokenRequestRequestObject) (HandleTokenRequestResponseObject, error) {
	ownDID, err := r.toOwnedDIDForOAuth2(ctx, request.Did)
	if err != nil {
		return nil, err
	}
	switch request.Body.GrantType {
	case "authorization_code":
		// Options:
		// - OpenID4VCI
		// - OpenID4VP
		// verifier DID is taken from code->oauthSession storage
		return r.handleAccessTokenRequest(ctx, *request.Body)
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
	if token.Get("status") == oauth.AccessTokenRequestStatusPending {
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
		Active:                  true,
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
			if _, exists := token.InputDescriptorConstraintIdMap[reserved]; exists {
				return nil, errors.New(fmt.Sprintf("IntrospectAccessToken: InputDescriptorConstraintIdMap contains reserved claim name '%s'", reserved))
			}
		}
		response.AdditionalProperties = token.InputDescriptorConstraintIdMap
	}

	return response, nil
}

// HandleAuthorizeRequest handles calls to the authorization endpoint for starting an authorization code flow.
func (r Wrapper) HandleAuthorizeRequest(ctx context.Context, request HandleAuthorizeRequestRequestObject) (HandleAuthorizeRequestResponseObject, error) {
	ownDID, err := r.toOwnedDIDForOAuth2(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	// Workaround: deepmap codegen doesn't support dynamic query parameters.
	//             See https://github.com/deepmap/oapi-codegen/issues/1129
	httpRequest := ctx.Value(httpRequestContextKey).(*http.Request)
	queryParams := httpRequest.URL.Query()

	// parse and validate as JAR (RFC9101, JWT Authorization Request)
	authzParams, err := r.jar.Parse(ctx, *ownDID, queryParams)
	if err != nil {
		return nil, err
	}

	session := createSession(authzParams, *ownDID)

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
			return r.handleAuthorizeRequestFromHolder(ctx, *ownDID, authzParams)
		} else {
			return nil, oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: "client_id must be a did:web",
			}
		}
	case responseTypeVPToken:
		// Options:
		// - OpenID4VP flow, vp_token is sent in Authorization Response
		return r.handleAuthorizeRequestFromVerifier(ctx, *ownDID, authzParams)
	default:
		// TODO: This should be a redirect?
		redirectURI, _ := url.Parse(session.RedirectURI)
		return nil, oauth.OAuth2Error{
			Code:        oauth.UnsupportedResponseType,
			RedirectURI: redirectURI,
		}
	}
}

// GetRequestJWT returns the Request Object referenced as 'request_uri' in an authorization request.
// RFC9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR).
func (r Wrapper) GetRequestJWT(ctx context.Context, request GetRequestJWTRequestObject) (GetRequestJWTResponseObject, error) {
	ro := new(jarRequest)
	err := r.authzRequestObjectStore().Get(request.Id, ro)
	if err != nil {
		return nil, err
	}
	// compare raw strings, don't waste a db call to see if we own the request.Did.
	if ro.Client.String() != request.Did {
		return nil, errors.New("invalid request")
	}
	if ro.RequestURIMethod != "get" {
		// TODO: wallet does not support `request_uri_method=post`. Signing the current jarRequest would leave it without 'aud'.
		//		 is this acceptable or should it fail?
		return nil, oauth.OAuth2Error{
			Code:          oauth.InvalidRequest,
			Description:   "used request_uri_method 'get' on a 'post' request_uri",
			InternalError: errors.New("wrong 'request_uri_method' authorization server or wallet probably does not support 'request_uri_method'"),
		}
	}
	token, err := r.jar.Sign(ctx, ro.Claims)
	if err != nil {
		// TODO: oauth.OAuth2Error?
		return nil, err
	}
	return GetRequestJWT200ApplicationoauthAuthzReqJwtResponse{
		Body:          bytes.NewReader([]byte(token)),
		ContentLength: int64(len(token)),
	}, nil
}

// PostRequestJWT returns the Request Object referenced as 'request_uri' in an authorization request.
// Extension of OpenID 4 Verifiable Presentations (OpenID4VP) on
// RFC9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR).
func (r Wrapper) PostRequestJWT(ctx context.Context, request PostRequestJWTRequestObject) (PostRequestJWTResponseObject, error) {
	return nil, errors.New("not implemented")
}

// OAuthAuthorizationServerMetadata returns the Authorization Server's metadata
func (r Wrapper) OAuthAuthorizationServerMetadata(ctx context.Context, request OAuthAuthorizationServerMetadataRequestObject) (OAuthAuthorizationServerMetadataResponseObject, error) {
	didAsString := r.requestedDID(request.Id).String()
	md, err := r.oauthAuthorizationServerMetadata(ctx, didAsString)
	if err != nil {
		return nil, err
	}
	return OAuthAuthorizationServerMetadata200JSONResponse(*md), nil
}

func (r Wrapper) RootOAuthAuthorizationServerMetadata(ctx context.Context, request RootOAuthAuthorizationServerMetadataRequestObject) (RootOAuthAuthorizationServerMetadataResponseObject, error) {
	md, err := r.oauthAuthorizationServerMetadata(ctx, r.requestedDID("").String())
	if err != nil {
		return nil, err
	}
	return RootOAuthAuthorizationServerMetadata200JSONResponse(*md), nil
}

func (r Wrapper) oauthAuthorizationServerMetadata(ctx context.Context, didAsString string) (*oauth.AuthorizationServerMetadata, error) {
	ownDID, err := r.toOwnedDID(ctx, didAsString)
	if err != nil {
		return nil, err
	}
	identity, err := didweb.DIDToURL(*ownDID)
	if err != nil {
		return nil, err
	}
	oauth2BaseURL, err := createOAuth2BaseURL(*ownDID)
	if err != nil {
		// can't fail, already did DIDToURL above
		return nil, err
	}
	md := authorizationServerMetadata(*identity, *oauth2BaseURL)
	return &md, nil
}

func (r Wrapper) GetTenantWebDID(_ context.Context, request GetTenantWebDIDRequestObject) (GetTenantWebDIDResponseObject, error) {
	ownDID := r.requestedDID(request.Id)
	document, err := r.vdr.ResolveManaged(ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return GetTenantWebDID404Response{}, nil
		}
		log.Logger().WithError(err).Errorf("Could not resolve tenant did:web: %s", ownDID.String())
		return nil, errors.New("unable to resolve DID")
	}
	return GetTenantWebDID200JSONResponse(*document), nil
}

func (r Wrapper) GetRootWebDID(ctx context.Context, _ GetRootWebDIDRequestObject) (GetRootWebDIDResponseObject, error) {
	ownDID := r.requestedDID("")
	document, err := r.vdr.ResolveManaged(ownDID)
	if err != nil {
		if resolver.IsFunctionalResolveError(err) {
			return GetRootWebDID404Response{}, nil
		}
		log.Logger().WithError(err).Errorf("Could not resolve root did:web: %s", ownDID.String())
		return nil, errors.New("unable to resolve DID")
	}
	return GetRootWebDID200JSONResponse(*document), nil
}

// OAuthClientMetadata returns the OAuth2 Client metadata for the request.Id if it is managed by this node.
func (r Wrapper) OAuthClientMetadata(ctx context.Context, request OAuthClientMetadataRequestObject) (OAuthClientMetadataResponseObject, error) {
	ownedDID, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	identityURL, err := createOAuth2BaseURL(*ownedDID)
	if err != nil {
		return nil, err
	}

	return OAuthClientMetadata200JSONResponse(clientMetadata(*identityURL)), nil
}
func (r Wrapper) PresentationDefinition(ctx context.Context, request PresentationDefinitionRequestObject) (PresentationDefinitionResponseObject, error) {
	if len(request.Params.Scope) == 0 {
		return PresentationDefinition200JSONResponse(PresentationDefinition{}), nil
	}

	authorizer, err := r.toOwnedDIDForOAuth2(ctx, request.Did)
	if err != nil {
		return nil, err
	}

	mapping, err := r.policyBackend.PresentationDefinitions(ctx, *authorizer, request.Params.Scope)
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

// toOwnedDIDForOAuth2 is like toOwnedDID but wraps the errors in oauth.OAuth2Error to make sure they're returned as specified by the OAuth2 RFC.
func (r Wrapper) toOwnedDIDForOAuth2(ctx context.Context, didAsString string) (*did.DID, error) {
	result, err := r.toOwnedDID(ctx, didAsString)
	if err != nil {
		if strings.HasPrefix(err.Error(), "DID resolution failed") {
			return nil, oauth.OAuth2Error{
				Code:        oauth.ServerError,
				Description: err.Error(),
			}
		} else {
			return nil, oauth.OAuth2Error{
				Code:        oauth.InvalidRequest,
				Description: err.Error(),
			}
		}
	}
	return result, nil
}

func (r Wrapper) toOwnedDID(ctx context.Context, didAsString string) (*did.DID, error) {
	ownDID, err := did.ParseDID(didAsString)
	if err != nil {
		return nil, fmt.Errorf("invalid DID: %s", err)
	}
	owned, err := r.vdr.IsOwner(ctx, *ownDID)
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

	// TODO: When we support authentication at an external IdP,
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
	sessionID := cryptoNuts.GenerateNonce()

	// generate a redirect token valid for 5 seconds
	token := cryptoNuts.GenerateNonce()
	err = r.userRedirectStore().Put(token, RedirectSession{
		AccessTokenRequest: request,
		SessionID:          sessionID,
		OwnDID:             *requestHolder,
	})
	if err != nil {
		return nil, err
	}
	tokenResponse := (&TokenResponse{}).With("status", oauth.AccessTokenRequestStatusPending)
	if err = r.accessTokenClientStore().Put(sessionID, tokenResponse); err != nil {
		return nil, err
	}

	// generate a link to the redirect endpoint
	webURL, err := createOAuth2BaseURL(*requestHolder)
	if err != nil {
		return nil, err
	}
	webURL = webURL.JoinPath("user")
	// redirect to generic user page, context of token will render correct page
	redirectURL := httpNuts.AddQueryParams(*webURL, map[string]string{
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
	session.RedirectURI = params.get(oauth.RedirectURIParam)
	session.OwnDID = &ownDID
	session.ResponseType = params.get(oauth.ResponseTypeParam)
	session.PKCEParams = PKCEParams{
		Challenge:       params.get(oauth.CodeChallengeParam),
		ChallengeMethod: params.get(oauth.CodeChallengeMethodParam),
	}

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

func (r Wrapper) RequestOid4vciCredentialIssuance(ctx context.Context, request RequestOid4vciCredentialIssuanceRequestObject) (RequestOid4vciCredentialIssuanceResponseObject, error) {
	if request.Body == nil {
		// why did oapi-codegen generate a pointer for the body??
		return nil, core.InvalidInputError("missing request body")
	}
	// Parse and check the requester
	requestHolder, err := r.toOwnedDID(ctx, request.Did)
	if err != nil {
		log.Logger().WithError(err).Errorf("problem with owner DID: %s", request.Did)
		return nil, core.NotFoundError("problem with owner DID: %s", err.Error())
	}

	// Parse the issuer
	issuerDid, err := did.ParseDID(request.Body.Issuer)
	if err != nil {
		log.Logger().WithError(err).Errorf("could not parse Issuer DID: %s", request.Body.Issuer)
		return nil, core.InvalidInputError("could not parse Issuer DID: %s", request.Body.Issuer)
	}
	// Fetch the endpoints
	authorizationEndpoint, tokenEndpoint, credentialEndpoint, err := r.openidIssuerEndpoints(ctx, *issuerDid)
	if err != nil {
		log.Logger().WithError(err).Errorf("cannot locate endpoints for did: %s", issuerDid.String())
		return nil, core.Error(http.StatusFailedDependency, "cannot locate endpoints for did: %s", issuerDid.String())
	}
	endpoint, err := url.Parse(authorizationEndpoint)
	if err != nil {
		log.Logger().WithError(err).Errorf("failed to parse the authorization_endpoint: %s", authorizationEndpoint)
		return nil, fmt.Errorf("failed to parse the authorization_endpoint: %s", authorizationEndpoint)
	}
	// Read and parse the authorization details
	authorizationDetails := []byte("[]")
	if len(request.Body.AuthorizationDetails) > 0 {
		authorizationDetails, _ = json.Marshal(request.Body.AuthorizationDetails)
	}
	// Generate the state and PKCE
	state := cryptoNuts.GenerateNonce()
	pkceParams := generatePKCEParams()
	if err != nil {
		log.Logger().WithError(err).Errorf("failed to create the PKCE parameters")
		return nil, err
	}
	// Figure out our own redirect URL by parsing the did:web and extracting the host.
	requesterDidUrl, err := didweb.DIDToURL(*requestHolder)
	if err != nil {
		log.Logger().WithError(err).Errorf("failed convert did (%s) to url", requestHolder.String())
		return nil, err
	}
	redirectUri, err := url.Parse(fmt.Sprintf("https://%s/iam/oid4vci/callback", requesterDidUrl.Host))
	if err != nil {
		log.Logger().WithError(err).Errorf("failed to create the url for host: %s", requesterDidUrl.Host)
		return nil, err
	}
	// Store the session
	err = r.oid4vciSssionStore().Put(state, &Oid4vciSession{
		HolderDid:                requestHolder,
		IssuerDid:                issuerDid,
		RemoteRedirectUri:        request.Body.RedirectUri,
		RedirectUri:              redirectUri.String(),
		PKCEParams:               pkceParams,
		IssuerTokenEndpoint:      tokenEndpoint,
		IssuerCredentialEndpoint: credentialEndpoint,
	})
	if err != nil {
		log.Logger().WithError(err).Errorf("failed to store the session")
		return nil, err
	}
	// Build the redirect URL, the client browser should be redirected to.
	redirectUrl := httpNuts.AddQueryParams(*endpoint, map[string]string{
		"response_type":         "code",
		"state":                 state,
		"client_id":             requestHolder.String(),
		"authorization_details": string(authorizationDetails),
		"redirect_uri":          redirectUri.String(),
		"code_challenge":        pkceParams.Challenge,
		"code_challenge_method": pkceParams.ChallengeMethod,
	})

	log.Logger().Debugf("generated the following redirect_uri for did %s, to issuer %s: %s", requestHolder.String(), issuerDid.String(), redirectUri.String())

	return RequestOid4vciCredentialIssuance200JSONResponse{
		RedirectURI: redirectUrl.String(),
	}, nil
}

func (r Wrapper) CallbackOid4vciCredentialIssuance(ctx context.Context, request CallbackOid4vciCredentialIssuanceRequestObject) (CallbackOid4vciCredentialIssuanceResponseObject, error) {
	state := request.Params.State
	oid4vciSession := Oid4vciSession{}
	err := r.oid4vciSssionStore().Get(state, &oid4vciSession)
	if err != nil {
		return nil, core.NotFoundError("Cannot locate active session for state: %s", state)
	}
	if request.Params.Error != nil {
		errorCode := oauth.ErrorCode(*request.Params.Error)
		errorDescription := ""
		if request.Params.ErrorDescription != nil {
			errorDescription = *request.Params.ErrorDescription
		} else {
			errorDescription = fmt.Sprintf("Issuer returned error code: %s", *request.Params.Error)
		}
		return nil, withCallbackURI(oauthError(errorCode, errorDescription), oid4vciSession.remoteRedirectUri())
	}
	code := request.Params.Code
	pkceParams := oid4vciSession.PKCEParams
	issuerDid := oid4vciSession.IssuerDid
	holderDid := oid4vciSession.HolderDid
	tokenEndpoint := oid4vciSession.IssuerTokenEndpoint
	credentialEndpoint := oid4vciSession.IssuerCredentialEndpoint
	if err != nil {
		log.Logger().WithError(err).Error("cannot fetch the right endpoints")
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("cannot fetch the right endpoints: %s", err.Error())), oid4vciSession.remoteRedirectUri())
	}
	response, err := r.auth.IAMClient().AccessToken(ctx, code, *issuerDid, oid4vciSession.RedirectUri, *holderDid, pkceParams.Verifier)
	if err != nil {
		log.Logger().WithError(err).Errorf("error while fetching the access_token from endpoint: %s", tokenEndpoint)
		return nil, withCallbackURI(oauthError(oauth.AccessDenied, fmt.Sprintf("error while fetching the access_token from endpoint: %s, error: %s", tokenEndpoint, err.Error())), oid4vciSession.remoteRedirectUri())
	}
	cNonce := response.Get(oauth.CNonceParam)
	proofJWT, err := r.proofJwt(ctx, *holderDid, *issuerDid, &cNonce)
	if err != nil {
		log.Logger().WithError(err).Error("error while building proof")
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while fetching the credential from endpoint %s, error: %s", credentialEndpoint, err.Error())), oid4vciSession.remoteRedirectUri())
	}
	credentials, err := r.auth.IAMClient().VerifiableCredentials(ctx, credentialEndpoint, response.AccessToken, proofJWT)
	if err != nil {
		log.Logger().WithError(err).Errorf("error while fetching the credential from endpoint: %s", credentialEndpoint)
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while fetching the credential from endpoint %s, error: %s", credentialEndpoint, err.Error())), oid4vciSession.remoteRedirectUri())
	}
	credential, err := vc.ParseVerifiableCredential(credentials.Credential)
	if err != nil {
		log.Logger().WithError(err).Errorf("error while parsing the credential: %s", credentials.Credential)
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while parsing the credential: %s, error: %s", credentials.Credential, err.Error())), oid4vciSession.remoteRedirectUri())
	}
	err = r.vcr.Verifier().Verify(*credential, true, true, nil)
	if err != nil {
		log.Logger().WithError(err).Errorf("error while verifying the credential from issuer: %s", credential.Issuer.String())
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while verifying the credential from issuer: %s, error: %s", credential.Issuer.String(), err.Error())), oid4vciSession.remoteRedirectUri())
	}
	err = r.vcr.Wallet().Put(ctx, *credential)
	if err != nil {
		log.Logger().WithError(err).Errorf("error while storing credential with id: %s", credential.ID)
		return nil, withCallbackURI(oauthError(oauth.ServerError, fmt.Sprintf("error while storing credential with id: %s, error: %s", credential.ID, err.Error())), oid4vciSession.remoteRedirectUri())
	}

	log.Logger().Debugf("stored the credential with id: %s, now redirecting to %s", credential.ID, oid4vciSession.RemoteRedirectUri)

	return CallbackOid4vciCredentialIssuance302Response{
		Headers: CallbackOid4vciCredentialIssuance302ResponseHeaders{Location: oid4vciSession.RemoteRedirectUri},
	}, nil
}

func (r Wrapper) openidIssuerEndpoints(ctx context.Context, issuerDid did.DID) (string, string, string, error) {
	metadata, err := r.auth.IAMClient().OpenIdCredentialIssuerMetadata(ctx, issuerDid)
	if err != nil {
		return "", "", "", err
	}
	for i := range metadata.AuthorizationServers {
		serverURL := metadata.AuthorizationServers[i]
		openIdConfiguration, err := r.auth.IAMClient().OpenIdConfiguration(ctx, serverURL)
		if err != nil {
			return "", "", "", err
		}
		authorizationEndpoint := openIdConfiguration.AuthorizationEndpoint
		tokenEndpoint := openIdConfiguration.TokenEndpoint
		credentialEndpoint := metadata.CredentialEndpoint
		return authorizationEndpoint, tokenEndpoint, credentialEndpoint, nil
	}
	err = errors.New(fmt.Sprintf("cannot locate any authorization endpoint in %s", issuerDid.String()))
	return "", "", "", err
}

// CreateAuthorizationRequest creates an OAuth2.0 authorizationRequest redirect URL that redirects to the authorization server.
// It can create both regular OAuth2 requests and OpenID4VP requests due to the RequestModifier.
// It's able to create an unsigned request and a signed request (JAR) based on the OAuth Server Metadata.
// By default, it adds the following parameters to a regular request:
// - client_id
// and to a signed request:
// - client_id
// - jwt.Issuer
// - jwt.Audience
// - nonce
// any of these params can be overridden by the requestObjectModifier.
func (r Wrapper) CreateAuthorizationRequest(ctx context.Context, client did.DID, server did.DID, modifier requestObjectModifier) (*url.URL, error) {
	// we want to make a call according to §4.1.1 of RFC6749, https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1
	// The URL should be listed in the verifier metadata under the "authorization_endpoint" key
	metadata, err := r.auth.IAMClient().AuthorizationServerMetadata(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve remote OAuth Authorization Server metadata: %w", err)
	}
	if len(metadata.AuthorizationEndpoint) == 0 {
		return nil, fmt.Errorf("no authorization endpoint found in metadata for %s", server)
	}
	endpoint, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization endpoint URL: %w", err)
	}

	// request_uri
	requestURIID := cryptoNuts.GenerateNonce()
	requestObj := r.jar.Create(client, &server, modifier)
	if err = r.authzRequestObjectStore().Put(requestURIID, requestObj); err != nil {
		return nil, err
	}
	baseURL, err := createOAuth2BaseURL(client)
	if err != nil {
		return nil, err
	}
	requestURI := baseURL.JoinPath("request.jwt", requestURIID)

	// JAR request
	params := map[string]string{
		oauth.ClientIDParam:         client.String(),
		oauth.RequestURIMethodParam: requestObj.RequestURIMethod,
		oauth.RequestURIParam:       requestURI.String(),
	}
	if metadata.RequireSignedRequestObject {
		redirectURL := httpNuts.AddQueryParams(*endpoint, params)
		return &redirectURL, nil
	}
	// else; unclear if AS has support for RFC9101, so also add all modifiers to the query itself
	// left here for completeness, node 2 node interaction always uses JAR since the AS metadata has it hardcoded
	// TODO: in the user flow we have no AS metadata, meaning that we add all params to the query.
	// 		 This is most likely going to fail on mobile devices due to request url length.
	modifier(params)
	redirectURL := httpNuts.AddQueryParams(*endpoint, params)
	return &redirectURL, nil
}

func (r *Wrapper) proofJwt(ctx context.Context, holderDid did.DID, audienceDid did.DID, nonce *string) (string, error) {
	// TODO: is this the right key type?
	kid, _, err := r.keyResolver.ResolveKey(holderDid, nil, resolver.NutsSigningKeyType)
	if err != nil {
		return "", fmt.Errorf("failed to resolve key for did (%s): %w", holderDid.String(), err)
	}
	jti, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	claims := map[string]interface{}{
		"iss": holderDid.String(),
		"aud": audienceDid.String(),
		"jti": jti.String(),
	}
	if nonce != nil {
		claims["nonce"] = nonce
	}
	proofJwt, err := r.jwtSigner.SignJWT(ctx, claims, nil, kid.String())
	if err != nil {
		return "", fmt.Errorf("failed to sign the JWT with kid (%s): %w", kid.String(), err)
	}
	return proofJwt, nil
}

// requestedDID constructs a did:web DID as it was requested by the API caller. It can be a DID with or without user path, e.g.:
// - did:web:example.com
// - did:web:example:iam:1234
// When userID is given, it's appended to the DID as `:iam:<userID>`. If it's absent, the DID is returned as is.
func (r Wrapper) requestedDID(userID string) did.DID {
	identityURL := r.identityURL(userID)
	result, _ := didweb.URLToDID(*identityURL)
	return *result
}

// identityURL is like requestedDID() but returns the base URL for the DID.
// It is used for resolving metadata and its did:web DID, using the configured Nuts node URL.
func (r Wrapper) identityURL(userID string) *url.URL {
	baseURL := r.auth.PublicURL()
	if userID == "" {
		return baseURL
	}
	return baseURL.JoinPath("iam", userID)
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

// createOAuth2BaseURL creates an OAuth2 base URL for an owned did:web DID
// It creates a URL in the following format: https://<did:web host>/oauth2/<did>
func createOAuth2BaseURL(webDID did.DID) (*url.URL, error) {
	didURL, err := didweb.DIDToURL(webDID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DID to URL: %w", err)
	}
	return didURL.Parse("/oauth2/" + webDID.String())
}

func (r Wrapper) oid4vciSssionStore() storage.SessionStore {
	return r.storageEngine.GetSessionDatabase().GetStore(oid4vciSessionValidity, "oid4vci")
}
