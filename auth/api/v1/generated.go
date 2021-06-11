// Package v1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package v1

import (
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
)

// Defines values for AccessTokenRequestFailedResponseError.
const (
	AccessTokenRequestFailedResponseErrorInvalidGrant AccessTokenRequestFailedResponseError = "invalid_grant"

	AccessTokenRequestFailedResponseErrorInvalidRequest AccessTokenRequestFailedResponseError = "invalid_request"

	AccessTokenRequestFailedResponseErrorUnsupportedGrantType AccessTokenRequestFailedResponseError = "unsupported_grant_type"
)

// Defines values for SignSessionRequestMeans.
const (
	SignSessionRequestMeansDummy SignSessionRequestMeans = "dummy"

	SignSessionRequestMeansIrma SignSessionRequestMeans = "irma"
)

// Defines values for SignSessionResponseMeans.
const (
	SignSessionResponseMeansDummy SignSessionResponseMeans = "dummy"

	SignSessionResponseMeansIrma SignSessionResponseMeans = "irma"
)

// Error response when access token request fails as described in rfc6749 sectionn 5.2
type AccessTokenRequestFailedResponse struct {
	Error AccessTokenRequestFailedResponseError `json:"error"`

	// Human-readable ASCII text providing additional information, used to assist the client developer in understanding the error that occurred.
	ErrorDescription string `json:"error_description"`
}

// AccessTokenRequestFailedResponseError defines model for AccessTokenRequestFailedResponse.Error.
type AccessTokenRequestFailedResponseError string

// Successful response as described in rfc6749 section 5.1
type AccessTokenResponse struct {

	// The access token issued by the authorization server.
	// Could be a signed JWT or a random number. It should not have a meaning to the client.
	AccessToken string `json:"access_token"`

	// The lifetime in seconds of the access token.
	ExpiresIn float32 `json:"expires_in"`

	// The type of the token issued
	TokenType string `json:"token_type"`
}

// Contract defines model for Contract.
type Contract struct {

	// Language of the contract in all caps.
	Language           ContractLanguage `json:"language"`
	SignerAttributes   *[]string        `json:"signer_attributes,omitempty"`
	Template           *string          `json:"template,omitempty"`
	TemplateAttributes *[]string        `json:"template_attributes,omitempty"`

	// Type of which contract to sign.
	Type ContractType `json:"type"`

	// Version of the contract.
	Version ContractVersion `json:"version"`
}

// Language of the contract in all caps.
type ContractLanguage string

// ContractResponse defines model for ContractResponse.
type ContractResponse struct {

	// Language of the contract in all caps.
	Language ContractLanguage `json:"language"`

	// The contract message.
	Message string `json:"message"`

	// Type of which contract to sign.
	Type ContractType `json:"type"`

	// Version of the contract.
	Version ContractVersion `json:"version"`
}

// Type of which contract to sign.
type ContractType string

// SoftwareVersion of the contract.
type ContractVersion string

// Request as described in RFC7523 section 2.1
type CreateAccessTokenRequest struct {

	// Base64 encoded JWT following rfc7523 and the Nuts documentation
	Assertion string `json:"assertion"`

	// always must contain the value "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantType string `json:"grant_type"`
}

// Request for a JWT Bearer Token. The Bearer Token can be used during a Access Token Request in the assertion field
type CreateJwtBearerTokenRequest struct {
	Actor     string `json:"actor"`
	Custodian string `json:"custodian"`

	// Base64 encoded IRMA contract conaining the identity of the performer
	Identity string `json:"identity"`

	// The service for which this access-token can be used. The right oauth endpoint is selected based on the service.
	Service string  `json:"service"`
	Subject *string `json:"subject,omitempty"`
}

// DrawUpContractRequest defines model for DrawUpContractRequest.
type DrawUpContractRequest struct {

	// Language of the contract in all caps.
	Language ContractLanguage `json:"language"`

	// Identifier of the legalEntity as registered in the Nuts registry.
	LegalEntity LegalEntity `json:"legalEntity"`

	// Type of which contract to sign.
	Type ContractType `json:"type"`

	// The duration this contract is valid, starting from validFrom or current time if validFrom is omitted. Uses this node default when omitted. Valid time units are: 's', 'm', 'h'
	ValidDuration *string `json:"validDuration,omitempty"`

	// validFrom describes the time from which this contract should be considered valid. Current time is used when omitted.
	ValidFrom *string `json:"validFrom,omitempty"`

	// Version of the contract.
	Version ContractVersion `json:"version"`
}

// Response with a JWT Bearer Token. It contains a JWT, signed with the private key of the requestor software vendor.
type JwtBearerTokenResponse struct {

	// The URL that corresponds to the oauth endpoint of the selected service.
	AuthorizationServerEndpoint string `json:"authorization_server_endpoint"`
	BearerToken                 string `json:"bearer_token"`
}

// Identifier of the legalEntity as registered in the Nuts registry.
type LegalEntity string

// SignSessionRequest defines model for SignSessionRequest.
type SignSessionRequest struct {
	Means SignSessionRequestMeans `json:"means"`

	// Params are passed to the means. Should be documented in the means documentation.
	Params map[string]interface{} `json:"params"`

	// Base64 encoded payload what needs to be signed.
	Payload string `json:"payload"`
}

// SignSessionRequestMeans defines model for SignSessionRequest.Means.
type SignSessionRequestMeans string

// SignSessionResponse defines model for SignSessionResponse.
type SignSessionResponse struct {

	// The means this session uses to sign.
	Means SignSessionResponseMeans `json:"means"`

	// Unique identifier of this sign session.
	SessionID string `json:"sessionID"`

	// A pointer to a sign session. This is an opaque value which only has meaning in the context of the signing means. Can be an URL, base64 encoded image of a QRCode etc.
	SessionPtr map[string]interface{} `json:"sessionPtr"`
}

// The means this session uses to sign.
type SignSessionResponseMeans string

// SignSessionStatusResponse defines model for SignSessionStatusResponse.
type SignSessionStatusResponse struct {

	// Status indicates the status of the signing proces. Values depend on the implementation of the signing means.
	Status string `json:"status"`

	// If the signature session is completed, this property contains the signature embedded in an w3c verifiable presentation.
	VerifiablePresentation *VerifiablePresentation `json:"verifiablePresentation,omitempty"`
}

// SignatureVerificationRequest defines model for SignatureVerificationRequest.
type SignatureVerificationRequest struct {

	// If the signature session is completed, this property contains the signature embedded in an w3c verifiable presentation.
	VerifiablePresentation VerifiablePresentation `json:"VerifiablePresentation"`

	// Moment in time to check the validity of the signature. If omitted, the current time is used.
	CheckTime *string `json:"checkTime,omitempty"`
}

// Contains the signature verification result.
type SignatureVerificationResponse struct {

	// Key value pairs containing claims and their values.
	Credentials *map[string]interface{} `json:"credentials,omitempty"`

	// Key vale pairs containing the attributes of the issuer.
	IssuerAttributes *map[string]interface{} `json:"issuerAttributes,omitempty"`

	// Indicates the validity of the signature.
	Validity bool `json:"validity"`

	// Type of Verifiable credential.
	VpType *string `json:"vpType,omitempty"`
}

// Token introspection request as described in RFC7662 section 2.1
type TokenIntrospectionRequest struct {
	Token string `json:"token"`
}

// Token introspection response as described in RFC7662 section 2.2
type TokenIntrospectionResponse struct {

	// True if the token is active, false if the token is expired, malformed etc.
	Active bool `json:"active"`

	// As per rfc7523 https://tools.ietf.org/html/rfc7523>, the aud must be the
	// token endpoint. This can be taken from the Nuts registry.
	Aud *string `json:"aud,omitempty"`

	// End-User's preferred e-mail address. Should be a personal email and can be used to uniquely identify a user. Just like the email used for an account.
	Email *string `json:"email,omitempty"`
	Exp   *int    `json:"exp,omitempty"`

	// Surname(s) or last name(s) of the End-User.
	FamilyName *string `json:"family_name,omitempty"`

	// Given name(s) or first name(s) of the End-User.
	GivenName *string `json:"given_name,omitempty"`
	Iat       *int    `json:"iat,omitempty"`

	// The subject (not a Nuts subject) contains the URN of the custodian.
	Iss *string `json:"iss,omitempty"`

	// End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
	Name *string `json:"name,omitempty"`

	// encoded ops signature. (TBD)
	Osi *string `json:"osi,omitempty"`

	// Surname prefix
	Prefix  *string `json:"prefix,omitempty"`
	Service *string `json:"service,omitempty"`

	// The Nuts subject id, patient identifier in the form of an oid encoded BSN.
	Sid *string `json:"sid,omitempty"`

	// The subject is always the acting party, thus the care organization requesting access to data.
	Sub *string `json:"sub,omitempty"`

	// Jwt encoded user identity.
	Usi *string `json:"usi,omitempty"`
}

// If the signature session is completed, this property contains the signature embedded in an w3c verifiable presentation.
type VerifiablePresentation struct {
	Context []string               `json:"@context"`
	Proof   map[string]interface{} `json:"proof"`
	Type    []string               `json:"type"`
}

// VerifyAccessTokenParams defines parameters for VerifyAccessToken.
type VerifyAccessTokenParams struct {
	Authorization string `json:"Authorization"`
}

// CreateJwtBearerTokenJSONBody defines parameters for CreateJwtBearerToken.
type CreateJwtBearerTokenJSONBody CreateJwtBearerTokenRequest

// DrawUpContractJSONBody defines parameters for DrawUpContract.
type DrawUpContractJSONBody DrawUpContractRequest

// CreateSignSessionJSONBody defines parameters for CreateSignSession.
type CreateSignSessionJSONBody SignSessionRequest

// VerifySignatureJSONBody defines parameters for VerifySignature.
type VerifySignatureJSONBody SignatureVerificationRequest

// CreateAccessTokenJSONBody defines parameters for CreateAccessToken.
type CreateAccessTokenJSONBody CreateAccessTokenRequest

// GetContractByTypeParams defines parameters for GetContractByType.
type GetContractByTypeParams struct {

	// The version of this contract. If omitted, the most recent version will be returned
	Version  *string `json:"version,omitempty"`
	Language *string `json:"language,omitempty"`
}

// CreateJwtBearerTokenJSONRequestBody defines body for CreateJwtBearerToken for application/json ContentType.
type CreateJwtBearerTokenJSONRequestBody CreateJwtBearerTokenJSONBody

// DrawUpContractJSONRequestBody defines body for DrawUpContract for application/json ContentType.
type DrawUpContractJSONRequestBody DrawUpContractJSONBody

// CreateSignSessionJSONRequestBody defines body for CreateSignSession for application/json ContentType.
type CreateSignSessionJSONRequestBody CreateSignSessionJSONBody

// VerifySignatureJSONRequestBody defines body for VerifySignature for application/json ContentType.
type VerifySignatureJSONRequestBody VerifySignatureJSONBody

// CreateAccessTokenJSONRequestBody defines body for CreateAccessToken for application/json ContentType.
type CreateAccessTokenJSONRequestBody CreateAccessTokenJSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Introspection endpoint to retrieve information from an Access Token as described by RFC7662
	// (POST /internal/auth/v1/accesstoken/introspect)
	IntrospectAccessToken(ctx echo.Context) error
	// Verifies the provided access token
	// (HEAD /internal/auth/v1/accesstoken/verify)
	VerifyAccessToken(ctx echo.Context, params VerifyAccessTokenParams) error
	// Create a JWT Bearer Token
	// (POST /internal/auth/v1/bearertoken)
	CreateJwtBearerToken(ctx echo.Context) error
	// Draw up a contract using a specified contract template, language and version
	// (PUT /internal/auth/v1/contract/drawup)
	DrawUpContract(ctx echo.Context) error
	// Create a signing session for a supported means.
	// (POST /internal/auth/v1/signature/session)
	CreateSignSession(ctx echo.Context) error
	// Get the current status of a signing session
	// (GET /internal/auth/v1/signature/session/{sessionID})
	GetSignSessionStatus(ctx echo.Context, sessionID string) error
	// Verify a signature in the form of a verifiable presentation
	// (PUT /internal/auth/v1/signature/verify)
	VerifySignature(ctx echo.Context) error
	// Create an access token based on the OAuth JWT Bearer flow.
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

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.IntrospectAccessToken(ctx)
	return err
}

// VerifyAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) VerifyAccessToken(ctx echo.Context) error {
	var err error

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

// CreateJwtBearerToken converts echo context to params.
func (w *ServerInterfaceWrapper) CreateJwtBearerToken(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateJwtBearerToken(ctx)
	return err
}

// DrawUpContract converts echo context to params.
func (w *ServerInterfaceWrapper) DrawUpContract(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.DrawUpContract(ctx)
	return err
}

// CreateSignSession converts echo context to params.
func (w *ServerInterfaceWrapper) CreateSignSession(ctx echo.Context) error {
	var err error

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

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetSignSessionStatus(ctx, sessionID)
	return err
}

// VerifySignature converts echo context to params.
func (w *ServerInterfaceWrapper) VerifySignature(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.VerifySignature(ctx)
	return err
}

// CreateAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) CreateAccessToken(ctx echo.Context) error {
	var err error

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

// PATCH: This template file was taken from pkg/codegen/templates/register.tmpl

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	Add(method string, path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
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
	router.Add(http.MethodPost, baseURL+"/internal/auth/v1/accesstoken/introspect", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("IntrospectAccessToken", context)
		return wrapper.IntrospectAccessToken(context)
	})
	router.Add(http.MethodHead, baseURL+"/internal/auth/v1/accesstoken/verify", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("VerifyAccessToken", context)
		return wrapper.VerifyAccessToken(context)
	})
	router.Add(http.MethodPost, baseURL+"/internal/auth/v1/bearertoken", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("CreateJwtBearerToken", context)
		return wrapper.CreateJwtBearerToken(context)
	})
	router.Add(http.MethodPut, baseURL+"/internal/auth/v1/contract/drawup", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("DrawUpContract", context)
		return wrapper.DrawUpContract(context)
	})
	router.Add(http.MethodPost, baseURL+"/internal/auth/v1/signature/session", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("CreateSignSession", context)
		return wrapper.CreateSignSession(context)
	})
	router.Add(http.MethodGet, baseURL+"/internal/auth/v1/signature/session/:sessionID", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("GetSignSessionStatus", context)
		return wrapper.GetSignSessionStatus(context)
	})
	router.Add(http.MethodPut, baseURL+"/internal/auth/v1/signature/verify", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("VerifySignature", context)
		return wrapper.VerifySignature(context)
	})
	router.Add(http.MethodPost, baseURL+"/n2n/auth/v1/accesstoken", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("CreateAccessToken", context)
		return wrapper.CreateAccessToken(context)
	})
	router.Add(http.MethodGet, baseURL+"/public/auth/v1/contract/:contractType", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("GetContractByType", context)
		return wrapper.GetContractByType(context)
	})

}
