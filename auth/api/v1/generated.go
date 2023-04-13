// Package v1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.4 DO NOT EDIT.
package v1

import (
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
)

const (
	JwtBearerAuthScopes = "jwtBearerAuth.Scopes"
)

// Defines values for AccessTokenRequestFailedResponseError.
const (
	InvalidGrant         AccessTokenRequestFailedResponseError = "invalid_grant"
	InvalidRequest       AccessTokenRequestFailedResponseError = "invalid_request"
	UnsupportedGrantType AccessTokenRequestFailedResponseError = "unsupported_grant_type"
)

// Defines values for SignSessionRequestMeans.
const (
	SignSessionRequestMeansDummy      SignSessionRequestMeans = "dummy"
	SignSessionRequestMeansIrma       SignSessionRequestMeans = "irma"
	SignSessionRequestMeansSelfsigned SignSessionRequestMeans = "selfsigned"
)

// Defines values for SignSessionResponseMeans.
const (
	SignSessionResponseMeansDummy      SignSessionResponseMeans = "dummy"
	SignSessionResponseMeansIrma       SignSessionResponseMeans = "irma"
	SignSessionResponseMeansSelfsigned SignSessionResponseMeans = "selfsigned"
)

// AccessTokenRequestFailedResponse Error response when access token request fails as described in rfc6749 section 5.2
type AccessTokenRequestFailedResponse struct {
	Error AccessTokenRequestFailedResponseError `json:"error"`

	// ErrorDescription Human-readable ASCII text providing additional information, used to assist the client developer in understanding the error that occurred.
	ErrorDescription string `json:"error_description"`
}

// AccessTokenRequestFailedResponseError defines model for AccessTokenRequestFailedResponse.Error.
type AccessTokenRequestFailedResponseError string

// Contract defines model for Contract.
type Contract struct {
	// Language Language of the contract in all caps.
	Language           ContractLanguage `json:"language"`
	SignerAttributes   *[]string        `json:"signer_attributes,omitempty"`
	Template           *string          `json:"template,omitempty"`
	TemplateAttributes *[]string        `json:"template_attributes,omitempty"`

	// Type Type of which contract to sign.
	Type ContractType `json:"type"`

	// Version Version of the contract.
	Version ContractVersion `json:"version"`
}

// ContractLanguage Language of the contract in all caps.
type ContractLanguage = string

// ContractResponse defines model for ContractResponse.
type ContractResponse struct {
	// Language Language of the contract in all caps.
	Language ContractLanguage `json:"language"`

	// Message The contract message.
	Message string `json:"message"`

	// Type Type of which contract to sign.
	Type ContractType `json:"type"`

	// Version Version of the contract.
	Version ContractVersion `json:"version"`
}

// ContractSigningRequest defines model for ContractSigningRequest.
type ContractSigningRequest struct {
	// Language Language of the contract in all caps.
	Language ContractLanguage `json:"language"`

	// LegalEntity DID of the organization as registered in the Nuts registry.
	LegalEntity LegalEntity `json:"legalEntity"`

	// Type Type of which contract to sign.
	Type ContractType `json:"type"`

	// ValidFrom ValidFrom describes the time from which this contract should be considered valid
	ValidFrom *string `json:"valid_from,omitempty"`

	// ValidTo ValidTo describes the time until this contract should be considered valid
	ValidTo *string `json:"valid_to,omitempty"`

	// Version Version of the contract.
	Version ContractVersion `json:"version"`
}

// ContractType Type of which contract to sign.
type ContractType = string

// ContractVersion Version of the contract.
type ContractVersion = string

// CreateAccessTokenRequest Request as described in RFC7523 section 2.1
type CreateAccessTokenRequest struct {
	// Assertion Base64 encoded JWT following rfc7523 and the Nuts documentation
	Assertion string `json:"assertion"`

	// GrantType always must contain the value "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantType string `json:"grant_type"`
}

// CreateJwtGrantRequest Request for a JWT Grant. The grant can be used during a Access Token Request in the assertion field
type CreateJwtGrantRequest struct {
	Authorizer  string                 `json:"authorizer"`
	Credentials []VerifiableCredential `json:"credentials"`

	// Identity Verifiable Presentation
	Identity  *VerifiablePresentation `json:"identity,omitempty"`
	Requester string                  `json:"requester"`

	// Service The service for which this access token can be used. The right oauth endpoint is selected based on the service.
	Service string `json:"service"`
}

// DrawUpContractRequest defines model for DrawUpContractRequest.
type DrawUpContractRequest struct {
	// Language Language of the contract in all caps.
	Language ContractLanguage `json:"language"`

	// LegalEntity DID of the organization as registered in the Nuts registry.
	LegalEntity LegalEntity `json:"legalEntity"`

	// OrganizationCredential A credential according to the W3C and Nuts specs.
	OrganizationCredential *VerifiableCredential `json:"organizationCredential,omitempty"`

	// Type Type of which contract to sign.
	Type ContractType `json:"type"`

	// ValidDuration The duration this contract is valid, starting from validFrom or current time if validFrom is omitted. Uses this node default when omitted. Valid time units are: 's', 'm', 'h'
	ValidDuration *string `json:"validDuration,omitempty"`

	// ValidFrom validFrom describes the time from which this contract should be considered valid. Current time is used when omitted.
	ValidFrom *string `json:"validFrom,omitempty"`

	// Version Version of the contract.
	Version ContractVersion `json:"version"`
}

// JwtGrantResponse Response with a JWT Grant. It contains a JWT, signed with the private key of the requestor software vendor.
type JwtGrantResponse struct {
	// AuthorizationServerEndpoint The URL that corresponds to the oauth endpoint of the selected service.
	AuthorizationServerEndpoint string `json:"authorization_server_endpoint"`
	BearerToken                 string `json:"bearer_token"`
}

// LegalEntity DID of the organization as registered in the Nuts registry.
type LegalEntity = string

// RequestAccessTokenRequest Request for a JWT Grant and use it as authorization grant to get the access token from the authorizer
type RequestAccessTokenRequest struct {
	Authorizer string `json:"authorizer"`

	// Credentials Verifiable Credentials to be included in the access token. If no VCs are to be included in the access token, the array can be left empty.
	Credentials []VerifiableCredential `json:"credentials"`

	// Identity Verifiable Presentation
	Identity  *VerifiablePresentation `json:"identity,omitempty"`
	Requester string                  `json:"requester"`

	// Service The service for which this access token can be used. The right oauth endpoint is selected based on the service.
	Service string `json:"service"`
}

// SignSessionRequest defines model for SignSessionRequest.
type SignSessionRequest struct {
	Means SignSessionRequestMeans `json:"means"`

	// Params Params are passed to the means. Should be documented in the means documentation.
	Params map[string]interface{} `json:"params"`

	// Payload Base64 encoded payload what needs to be signed.
	Payload string `json:"payload"`
}

// SignSessionRequestMeans defines model for SignSessionRequest.Means.
type SignSessionRequestMeans string

// SignSessionResponse defines model for SignSessionResponse.
type SignSessionResponse struct {
	// Means The means this session uses to sign.
	Means SignSessionResponseMeans `json:"means"`

	// SessionID Unique identifier of this sign session.
	SessionID string `json:"sessionID"`

	// SessionPtr A pointer to a sign session. This is an opaque value which only has meaning in the context of the signing means. Can be an URL, base64 encoded image of a QRCode etc.
	SessionPtr map[string]interface{} `json:"sessionPtr"`
}

// SignSessionResponseMeans The means this session uses to sign.
type SignSessionResponseMeans string

// SignSessionStatusResponse defines model for SignSessionStatusResponse.
type SignSessionStatusResponse struct {
	// Status Status indicates the status of the signing process. Values depend on the implementation of the signing means.
	Status string `json:"status"`

	// VerifiablePresentation Verifiable Presentation
	VerifiablePresentation *VerifiablePresentation `json:"verifiablePresentation,omitempty"`
}

// SignatureVerificationRequest defines model for SignatureVerificationRequest.
type SignatureVerificationRequest struct {
	// VerifiablePresentation Verifiable Presentation
	VerifiablePresentation VerifiablePresentation `json:"VerifiablePresentation"`

	// CheckTime Moment in time to check the validity of the signature. If omitted, the current time is used.
	CheckTime *string `json:"checkTime,omitempty"`
}

// SignatureVerificationResponse Contains the signature verification result.
type SignatureVerificationResponse struct {
	// Credentials Key value pairs containing claims and their values.
	Credentials *map[string]interface{} `json:"credentials,omitempty"`

	// IssuerAttributes Key vale pairs containing the attributes of the issuer.
	IssuerAttributes *map[string]interface{} `json:"issuerAttributes,omitempty"`

	// Validity Indicates the validity of the signature.
	Validity bool `json:"validity"`

	// VpType Type of Verifiable credential.
	VpType *string `json:"vpType,omitempty"`
}

// TokenIntrospectionRequest Token introspection request as described in RFC7662 section 2.1
type TokenIntrospectionRequest struct {
	Token string `json:"token"`
}

// TokenIntrospectionResponse Token introspection response as described in RFC7662 section 2.2
type TokenIntrospectionResponse struct {
	// Active True if the token is active, false if the token is expired, malformed etc.
	Active bool `json:"active"`

	// Aud As per rfc7523 https://tools.ietf.org/html/rfc7523>, the aud must be the
	// token endpoint. This can be taken from the Nuts registry.
	Aud *string `json:"aud,omitempty"`

	// Email End-User's preferred e-mail address. Should be a personal email and can be used to uniquely identify a user. Just like the email used for an account.
	Email *string `json:"email,omitempty"`
	Exp   *int    `json:"exp,omitempty"`

	// FamilyName Surname(s) or last name(s) of the End-User.
	FamilyName *string `json:"family_name,omitempty"`
	Iat        *int    `json:"iat,omitempty"`

	// Initials Initials of the End-User.
	Initials *string `json:"initials,omitempty"`

	// Iss The subject (not a Nuts subject) contains the DID of the authorizer.
	Iss *string `json:"iss,omitempty"`

	// Osi encoded ops signature. (TBD)
	Osi *string `json:"osi,omitempty"`

	// Prefix Surname prefix
	Prefix *string `json:"prefix,omitempty"`

	// ResolvedVCs credentials resolved from `vcs` (VC IDs). It contains only those VCs that could be resolved.
	ResolvedVCs *[]VerifiableCredential `json:"resolvedVCs,omitempty"`
	Service     *string                 `json:"service,omitempty"`

	// Sub The subject is always the acting party, thus the care organization requesting access to data.
	Sub *string   `json:"sub,omitempty"`
	Vcs *[]string `json:"vcs,omitempty"`
}

// IntrospectAccessTokenFormdataBody defines parameters for IntrospectAccessToken.
type IntrospectAccessTokenFormdataBody struct {
	// Token JWT access token
	Token string `json:"token"`
}

// VerifyAccessTokenParams defines parameters for VerifyAccessToken.
type VerifyAccessTokenParams struct {
	Authorization string `json:"Authorization"`
}

// GetContractByTypeParams defines parameters for GetContractByType.
type GetContractByTypeParams struct {
	// Version The version of this contract. If omitted, the most recent version will be returned
	Version  *string `form:"version,omitempty" json:"version,omitempty"`
	Language *string `form:"language,omitempty" json:"language,omitempty"`
}

// IntrospectAccessTokenFormdataRequestBody defines body for IntrospectAccessToken for application/x-www-form-urlencoded ContentType.
type IntrospectAccessTokenFormdataRequestBody IntrospectAccessTokenFormdataBody

// DrawUpContractJSONRequestBody defines body for DrawUpContract for application/json ContentType.
type DrawUpContractJSONRequestBody = DrawUpContractRequest

// CreateJwtGrantJSONRequestBody defines body for CreateJwtGrant for application/json ContentType.
type CreateJwtGrantJSONRequestBody = CreateJwtGrantRequest

// RequestAccessTokenJSONRequestBody defines body for RequestAccessToken for application/json ContentType.
type RequestAccessTokenJSONRequestBody = RequestAccessTokenRequest

// CreateSignSessionJSONRequestBody defines body for CreateSignSession for application/json ContentType.
type CreateSignSessionJSONRequestBody = SignSessionRequest

// VerifySignatureJSONRequestBody defines body for VerifySignature for application/json ContentType.
type VerifySignatureJSONRequestBody = SignatureVerificationRequest

// CreateAccessTokenFormdataRequestBody defines body for CreateAccessToken for application/x-www-form-urlencoded ContentType.
type CreateAccessTokenFormdataRequestBody = CreateAccessTokenRequest

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Introspection endpoint to retrieve information from an Access Token as described by RFC7662
	// (POST /internal/auth/v1/accesstoken/introspect)
	IntrospectAccessToken(ctx echo.Context) error
	// Verifies the provided access token
	// (HEAD /internal/auth/v1/accesstoken/verify)
	VerifyAccessToken(ctx echo.Context, params VerifyAccessTokenParams) error
	// Draw up a contract using a specified contract template, language and version
	// (PUT /internal/auth/v1/contract/drawup)
	DrawUpContract(ctx echo.Context) error
	// Create a JWT Grant
	// (POST /internal/auth/v1/jwt-grant)
	CreateJwtGrant(ctx echo.Context) error
	// Request an access token from the authorizer
	// (POST /internal/auth/v1/request-access-token)
	RequestAccessToken(ctx echo.Context) error
	// Create a signing session for a supported means.
	// (POST /internal/auth/v1/signature/session)
	CreateSignSession(ctx echo.Context) error
	// Get the current status of a signing session
	// (GET /internal/auth/v1/signature/session/{sessionID})
	GetSignSessionStatus(ctx echo.Context, sessionID string) error
	// Verify a signature in the form of a verifiable presentation
	// (PUT /internal/auth/v1/signature/verify)
	VerifySignature(ctx echo.Context) error
	// Create an access token using a JWT as authorization grant
	// (POST /n2n/auth/v1/accesstoken)
	CreateAccessToken(ctx echo.Context) error
	// Get a contract by type and version
	// (GET /public/auth/v1/contract/{contractType})
	GetContractByType(ctx echo.Context, contractType string, params GetContractByTypeParams) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// IntrospectAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) IntrospectAccessToken(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.IntrospectAccessToken(ctx)
	return err
}

// VerifyAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) VerifyAccessToken(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Parameter object where we will unmarshal all parameters from the context
	var params VerifyAccessTokenParams

	headers := ctx.Request().Header
	// ------------- Required header parameter "Authorization" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("Authorization")]; found {
		var Authorization string
		n := len(valueList)
		if n != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Expected one value for Authorization, got %d", n))
		}

		err = runtime.BindStyledParameterWithLocation("simple", false, "Authorization", runtime.ParamLocationHeader, valueList[0], &Authorization)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter Authorization: %s", err))
		}

		params.Authorization = Authorization
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Header parameter Authorization is required, but not found"))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.VerifyAccessToken(ctx, params)
	return err
}

// DrawUpContract converts echo context to params.
func (w *ServerInterfaceWrapper) DrawUpContract(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.DrawUpContract(ctx)
	return err
}

// CreateJwtGrant converts echo context to params.
func (w *ServerInterfaceWrapper) CreateJwtGrant(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateJwtGrant(ctx)
	return err
}

// RequestAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) RequestAccessToken(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.RequestAccessToken(ctx)
	return err
}

// CreateSignSession converts echo context to params.
func (w *ServerInterfaceWrapper) CreateSignSession(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateSignSession(ctx)
	return err
}

// GetSignSessionStatus converts echo context to params.
func (w *ServerInterfaceWrapper) GetSignSessionStatus(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "sessionID" -------------
	var sessionID string

	err = runtime.BindStyledParameterWithLocation("simple", false, "sessionID", runtime.ParamLocationPath, ctx.Param("sessionID"), &sessionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter sessionID: %s", err))
	}

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetSignSessionStatus(ctx, sessionID)
	return err
}

// VerifySignature converts echo context to params.
func (w *ServerInterfaceWrapper) VerifySignature(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.VerifySignature(ctx)
	return err
}

// CreateAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) CreateAccessToken(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateAccessToken(ctx)
	return err
}

// GetContractByType converts echo context to params.
func (w *ServerInterfaceWrapper) GetContractByType(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "contractType" -------------
	var contractType string

	err = runtime.BindStyledParameterWithLocation("simple", false, "contractType", runtime.ParamLocationPath, ctx.Param("contractType"), &contractType)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter contractType: %s", err))
	}

	ctx.Set(JwtBearerAuthScopes, []string{""})

	// Parameter object where we will unmarshal all parameters from the context
	var params GetContractByTypeParams
	// ------------- Optional query parameter "version" -------------

	err = runtime.BindQueryParameter("form", true, false, "version", ctx.QueryParams(), &params.Version)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter version: %s", err))
	}

	// ------------- Optional query parameter "language" -------------

	err = runtime.BindQueryParameter("form", true, false, "language", ctx.QueryParams(), &params.Language)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter language: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetContractByType(ctx, contractType, params)
	return err
}

// PATCH: This template file was taken from pkg/codegen/templates/echo/echo-register.tmpl

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

type Preprocessor interface {
	Preprocess(operationID string, context echo.Context)
}

type ErrorStatusCodeResolver interface {
	ResolveStatusCode(err error) int
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface) {
	RegisterHandlersWithBaseURL(router, si, "")
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	// PATCH: This alteration wraps the call to the implementation in a function that sets the "OperationId" context parameter,
	// so it can be used in error reporting middleware.
	router.POST(baseURL+"/internal/auth/v1/accesstoken/introspect", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("IntrospectAccessToken", context)
		return wrapper.IntrospectAccessToken(context)
	})
	router.HEAD(baseURL+"/internal/auth/v1/accesstoken/verify", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("VerifyAccessToken", context)
		return wrapper.VerifyAccessToken(context)
	})
	router.PUT(baseURL+"/internal/auth/v1/contract/drawup", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("DrawUpContract", context)
		return wrapper.DrawUpContract(context)
	})
	router.POST(baseURL+"/internal/auth/v1/jwt-grant", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("CreateJwtGrant", context)
		return wrapper.CreateJwtGrant(context)
	})
	router.POST(baseURL+"/internal/auth/v1/request-access-token", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("RequestAccessToken", context)
		return wrapper.RequestAccessToken(context)
	})
	router.POST(baseURL+"/internal/auth/v1/signature/session", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("CreateSignSession", context)
		return wrapper.CreateSignSession(context)
	})
	router.GET(baseURL+"/internal/auth/v1/signature/session/:sessionID", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("GetSignSessionStatus", context)
		return wrapper.GetSignSessionStatus(context)
	})
	router.PUT(baseURL+"/internal/auth/v1/signature/verify", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("VerifySignature", context)
		return wrapper.VerifySignature(context)
	})
	router.POST(baseURL+"/n2n/auth/v1/accesstoken", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("CreateAccessToken", context)
		return wrapper.CreateAccessToken(context)
	})
	router.GET(baseURL+"/public/auth/v1/contract/:contractType", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("GetContractByType", context)
		return wrapper.GetContractByType(context)
	})

}
