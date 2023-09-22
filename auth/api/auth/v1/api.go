/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
 */

package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/audit"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/api/auth/v1/client"
	"github.com/nuts-foundation/nuts-node/vcr"

	"github.com/labstack/echo/v4"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/core"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

const (
	errOauthInvalidRequest   = "invalid_request"
	errOauthInvalidGrant     = "invalid_grant"
	errOauthUnsupportedGrant = "unsupported_grant_type"
	bearerTokenHeaderPrefix  = "bearer "
)

// Wrapper bridges the generated api types and http logic to the internal types and logic.
// It checks required parameters and message body. It converts data from api to internal types.
// Then passes the internal formats to the AuthenticationServices. Converts internal results back to the generated
// Api types. Handles errors and returns the correct http response. It does not perform any business logic.
type Wrapper struct {
	Auth               auth.AuthenticationServices
	CredentialResolver vcr.Resolver
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	return core.ResolveStatusCode(err, map[error]int{
		services.ErrSessionNotFound:            http.StatusNotFound,
		did.ErrInvalidDID:                      http.StatusBadRequest,
		services.InvalidContractRequestError{}: http.StatusBadRequest,
	})
}

// Routes registers the Echo routes for the API.
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, auth.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return audit.StrictMiddleware(f, auth.ModuleName, operationID)
		},
	}))
}

// VerifySignature handles the VerifySignature http request.
// It parses the request body, parses the verifiable presentation and calls the ContractNotary to verify the VP.
func (w Wrapper) VerifySignature(_ context.Context, request VerifySignatureRequestObject) (VerifySignatureResponseObject, error) {
	var err error
	checkTime := time.Now()
	if request.Body.CheckTime != nil {
		checkTime, err = time.Parse(time.RFC3339, *request.Body.CheckTime)
		if err != nil {
			return nil, core.InvalidInputError("could not parse checkTime: %w", err)
		}
	}
	validationResult, err := w.Auth.ContractNotary().VerifyVP(request.Body.VerifiablePresentation, &checkTime)
	if err != nil {
		return nil, core.InvalidInputError("unable to verify the verifiable presentation: %w", err)
	}
	// Convert internal validationResult to api SignatureVerificationResponse
	response := SignatureVerificationResponse{}
	if validationResult.Validity() == contract.Valid {
		response.Validity = true

		credentials := map[string]interface{}{}
		for key, val := range validationResult.ContractAttributes() {
			credentials[key] = val
		}
		response.Credentials = &credentials

		issuerAttributes := map[string]interface{}{}
		for key, val := range validationResult.DisclosedAttributes() {
			issuerAttributes[key] = val
		}
		response.IssuerAttributes = &issuerAttributes

		vpType := validationResult.VPType()
		response.VpType = &vpType
	} else {
		response.Validity = false
	}
	return VerifySignature200JSONResponse(response), nil
}

// CreateSignSession handles the CreateSignSession http request. It parses the parameters, finds the means handler and returns a session pointer which can be used to monitor the session.
func (w Wrapper) CreateSignSession(_ context.Context, request CreateSignSessionRequestObject) (CreateSignSessionResponseObject, error) {
	createSessionRequest := services.CreateSessionRequest{
		SigningMeans: string(request.Body.Means),
		Message:      request.Body.Payload,
		Params:       request.Body.Params,
	}
	sessionPtr, err := w.Auth.ContractNotary().CreateSigningSession(createSessionRequest)
	if err != nil {
		return nil, core.InvalidInputError("unable to create sign challenge: %w", err)
	}

	var keyValPointer map[string]interface{}
	err = convertToMap(sessionPtr, &keyValPointer)
	if err != nil {
		return nil, core.InvalidInputError("unable to build sessionPointer: %w", err)
	}

	response := SignSessionResponse{
		SessionID:  sessionPtr.SessionID(),
		Means:      SignSessionResponseMeans(request.Body.Means),
		SessionPtr: keyValPointer,
	}
	return CreateSignSession201JSONResponse(response), nil
}

// GetSignSessionStatus handles the http requests for getting the current status of a signing session.
func (w Wrapper) GetSignSessionStatus(ctx context.Context, request GetSignSessionStatusRequestObject) (GetSignSessionStatusResponseObject, error) {
	sessionStatus, err := w.Auth.ContractNotary().SigningSessionStatus(ctx, request.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session status for %s, reason: %w", request.SessionID, err)
	}
	vp, err := sessionStatus.VerifiablePresentation()
	if err != nil {
		return nil, fmt.Errorf("error while building verifiable presentation: %w", err)
	}
	var apiVp *VerifiablePresentation
	if vp != nil {
		apiVp = &VerifiablePresentation{}
		err = convertToMap(vp, apiVp)
		if err != nil {
			return nil, fmt.Errorf("unable to convert verifiable presentation: %w", err)
		}
	}
	response := SignSessionStatusResponse{Status: sessionStatus.Status(), VerifiablePresentation: apiVp}
	return GetSignSessionStatus200JSONResponse(response), nil
}

// GetContractByType handles the http request for finding a contract by type.
func (w Wrapper) GetContractByType(_ context.Context, request GetContractByTypeRequestObject) (GetContractByTypeResponseObject, error) {
	// convert generated data types to internal types
	var (
		contractLanguage contract.Language
		contractVersion  contract.Version
	)
	if request.Params.Language != nil {
		contractLanguage = contract.Language(*request.Params.Language)
	}

	if request.Params.Version != nil {
		contractVersion = contract.Version(*request.Params.Version)
	}

	// get contract
	authContract := contract.StandardContractTemplates.Get(contract.Type(request.ContractType), contractLanguage, contractVersion)
	if authContract == nil {
		return nil, core.NotFoundError("could not find contract template")
	}

	// convert internal data types to generated api types
	answer := Contract{
		Language:           ContractLanguage(authContract.Language),
		Template:           &authContract.Template,
		TemplateAttributes: &authContract.TemplateAttributes,
		Type:               ContractType(authContract.Type),
		Version:            ContractVersion(authContract.Version),
	}

	return GetContractByType200JSONResponse(answer), nil
}

// DrawUpContract handles the http request for drawing up a contract for a given contract template identified by type, language and version.
func (w Wrapper) DrawUpContract(ctx context.Context, request DrawUpContractRequestObject) (DrawUpContractResponseObject, error) {
	var (
		vf            time.Time
		validDuration time.Duration
		err           error
	)
	if request.Body.ValidFrom != nil {
		vf, err = time.Parse(time.RFC3339, *request.Body.ValidFrom)
		if err != nil {
			return nil, core.InvalidInputError("could not parse validFrom: %w", err)
		}
	} else {
		vf = time.Now()
	}

	if request.Body.ValidDuration != nil {
		validDuration, err = time.ParseDuration(*request.Body.ValidDuration)
		if err != nil {
			return nil, core.InvalidInputError("could not parse validDuration: %w", err)
		}
	}

	template := contract.StandardContractTemplates.Get(contract.Type(request.Body.Type), contract.Language(request.Body.Language), contract.Version(request.Body.Version))
	if template == nil {
		return nil, core.NotFoundError("no contract found for given combination of type, version, and language")
	}
	orgID, err := did.ParseDID(request.Body.LegalEntity)
	if err != nil {
		return nil, core.InvalidInputError("invalid value '%s' for param legalEntity: %w", request.Body.LegalEntity, err)
	}

	drawnUpContract, err := w.Auth.ContractNotary().DrawUpContract(ctx, *template, *orgID, vf, validDuration, request.Body.OrganizationCredential)
	if err != nil {
		return nil, err
	}

	response := ContractResponse{
		Language: ContractLanguage(drawnUpContract.Template.Language),
		Message:  drawnUpContract.RawContractText,
		Type:     ContractType(drawnUpContract.Template.Type),
		Version:  ContractVersion(drawnUpContract.Template.Version),
	}
	return DrawUpContract200JSONResponse(response), nil
}

// CreateJwtGrant handles the http request (from the vendor's EPD/XIS) for creating a JWT bearer token which can be used to retrieve an access token from a remote Nuts node.
func (w Wrapper) CreateJwtGrant(ctx context.Context, request CreateJwtGrantRequestObject) (CreateJwtGrantResponseObject, error) {

	req := services.CreateJwtGrantRequest{
		Requester:   request.Body.Requester,
		Authorizer:  request.Body.Authorizer,
		IdentityVP:  request.Body.Identity,
		Service:     request.Body.Service,
		Credentials: request.Body.Credentials,
	}

	response, err := w.Auth.RelyingParty().CreateJwtGrant(ctx, req)
	if err != nil {
		return nil, core.InvalidInputError(err.Error())
	}

	return CreateJwtGrant200JSONResponse{BearerToken: response.BearerToken, AuthorizationServerEndpoint: response.AuthorizationServerEndpoint}, nil
}

// RequestAccessToken handles the HTTP request (from the vendor's EPD/XIS) for creating a JWT grant and using it as authorization grant to get an access token from the remote Nuts node.
func (w Wrapper) RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error) {
	req := services.CreateJwtGrantRequest{
		Requester:   request.Body.Requester,
		Authorizer:  request.Body.Authorizer,
		IdentityVP:  request.Body.Identity,
		Service:     request.Body.Service,
		Credentials: request.Body.Credentials,
	}

	jwtGrant, err := w.Auth.RelyingParty().CreateJwtGrant(ctx, req)
	if err != nil {
		return nil, core.InvalidInputError(err.Error())
	}

	authServerEndpoint, err := url.Parse(jwtGrant.AuthorizationServerEndpoint)
	if err != nil {
		return nil, core.InvalidInputError("invalid authorization server endpoint: %s", jwtGrant.AuthorizationServerEndpoint)
	}

	accessTokenResult, err := w.Auth.RelyingParty().RequestRFC003AccessToken(ctx, jwtGrant.BearerToken, *authServerEndpoint)
	if err != nil {
		return nil, core.Error(http.StatusServiceUnavailable, err.Error())
	}
	return RequestAccessToken200JSONResponse(*accessTokenResult), nil
}

// CreateAccessToken handles the http request (from a remote vendor's Nuts node) for creating an access token for accessing
// resources of the local vendor's EPD/XIS. It consumes a JWT Bearer token.
// It consumes and checks the JWT and returns a smaller sessionToken
// The errors returns for this API do not follow RFC7807 but follow the oauth framework error response: RFC6749 (https://tools.ietf.org/html/rfc6749#page-45)
func (w Wrapper) CreateAccessToken(ctx context.Context, request CreateAccessTokenRequestObject) (CreateAccessTokenResponseObject, error) {

	if request.Body.GrantType != client.JwtBearerGrantType {
		errDesc := fmt.Sprintf("grant_type must be: '%s'", client.JwtBearerGrantType)
		errorResponse := AccessTokenRequestFailedResponse{Error: errOauthUnsupportedGrant, ErrorDescription: errDesc}
		return CreateAccessToken400JSONResponse(errorResponse), nil
	}

	const jwtPattern = `^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`
	if matched, err := regexp.Match(jwtPattern, []byte(request.Body.Assertion)); !matched || err != nil {
		errDesc := "Assertion must be a valid encoded jwt"
		errorResponse := AccessTokenRequestFailedResponse{Error: errOauthInvalidGrant, ErrorDescription: errDesc}
		return CreateAccessToken400JSONResponse(errorResponse), nil
	}

	catRequest := services.CreateAccessTokenRequest{RawJwtBearerToken: request.Body.Assertion}
	acResponse, oauthError := w.Auth.AuthzServer().CreateAccessToken(ctx, catRequest)
	if oauthError != nil {
		errorResponse := AccessTokenRequestFailedResponse{Error: AccessTokenRequestFailedResponseError(oauthError.Code), ErrorDescription: oauthError.Error()}
		return CreateAccessToken400JSONResponse(errorResponse), nil
	}
	response := AccessTokenResponse{
		AccessToken: acResponse.AccessToken,
		ExpiresIn:   acResponse.ExpiresIn,
		TokenType:   "bearer", // bearer token type according to RFC6750/RFC6749
	}

	return CreateAccessToken200JSONResponse(response), nil
}

// VerifyAccessToken handles the http request (from the vendor's EPD/XIS) for verifying an access token received from a remote Nuts node.
func (w Wrapper) VerifyAccessToken(ctx context.Context, request VerifyAccessTokenRequestObject) (VerifyAccessTokenResponseObject, error) {
	if len(request.Params.Authorization) == 0 {
		log.Logger().Warn("No authorization header given")
		return VerifyAccessToken403Response{}, nil
	}

	index := strings.Index(strings.ToLower(request.Params.Authorization), bearerTokenHeaderPrefix)
	if index != 0 {
		log.Logger().Warn("Authorization does not contain bearer token")
		return VerifyAccessToken403Response{}, nil
	}

	token := request.Params.Authorization[len(bearerTokenHeaderPrefix):]

	_, err := w.Auth.AuthzServer().IntrospectAccessToken(ctx, token)
	if err != nil {
		log.Logger().WithError(err).Warn("Error while inspecting access token")
		return VerifyAccessToken403Response{}, nil
	}

	return VerifyAccessToken200Response{}, nil
}

// IntrospectAccessToken handles the http request (from the vendor's EPD/XIS) for introspecting an access token received from a remote Nuts node.
func (w Wrapper) IntrospectAccessToken(ctx context.Context, request IntrospectAccessTokenRequestObject) (IntrospectAccessTokenResponseObject, error) {
	token := request.Body.Token

	introspectionResponse := TokenIntrospectionResponse{
		Active: false,
	}

	if len(token) == 0 {
		log.Logger().Warn("Missing token for introspection")
		return IntrospectAccessToken200JSONResponse(introspectionResponse), nil
	}

	claims, err := w.Auth.AuthzServer().IntrospectAccessToken(ctx, token)
	if err != nil {
		log.Logger().WithError(err).Warn("Error while inspecting access token")
		return IntrospectAccessToken200JSONResponse(introspectionResponse), nil
	}

	exp := int(claims.Expiration)
	iat := int(claims.IssuedAt)

	introspectionResponse = TokenIntrospectionResponse{
		Active:     true,
		Sub:        &claims.Subject,
		Iss:        &claims.Issuer,
		Aud:        &claims.Audience,
		Exp:        &exp,
		Iat:        &iat,
		Service:    &claims.Service,
		Initials:   claims.Initials,
		Prefix:     claims.Prefix,
		FamilyName: claims.FamilyName,
		Email:      claims.Email,
		Username:   claims.Username,
		UserRole:   claims.UserRole,
	}
	if claims.AssuranceLevel != nil {
		level := TokenIntrospectionResponseAssuranceLevel(*claims.AssuranceLevel)
		introspectionResponse.AssuranceLevel = &level
	}

	if claims.Credentials != nil && len(claims.Credentials) > 0 {
		introspectionResponse.Vcs = &claims.Credentials

		var resolvedVCs []VerifiableCredential
		for _, credentialID := range claims.Credentials {
			credential, err := w.resolveCredential(credentialID)
			if err != nil {
				log.Logger().
					WithError(err).
					WithField(core.LogFieldCredentialID, credentialID).
					Warn("Error while resolving credential")
				continue
			}
			resolvedVCs = append(resolvedVCs, *credential)
		}
		introspectionResponse.ResolvedVCs = &resolvedVCs
	}

	return IntrospectAccessToken200JSONResponse(introspectionResponse), nil
}

func (w *Wrapper) resolveCredential(credentialID string) (*vc.VerifiableCredential, error) {
	id, err := ssi.ParseURI(credentialID)
	if err != nil {
		return nil, err
	}
	return w.CredentialResolver.Resolve(*id, nil)
}

// convertToMap converts an object to a map[string]interface{} using json conversion
func convertToMap(obj interface{}, target interface{}) error {
	jsonStr, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("could not convert value to json: %w", err)
	}
	if err := json.Unmarshal(jsonStr, target); err != nil {
		return fmt.Errorf("could not convert json string to key value map: %w", err)
	}
	return nil
}
