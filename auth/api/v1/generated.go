// Package v1 provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package v1

import (
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
)

// AccessTokenRequestFailedResponse defines model for AccessTokenRequestFailedResponse.
type AccessTokenRequestFailedResponse struct {
	Error string `json:"error"`

	// Human-readable ASCII text providing additional information, used to assist the client developer in understanding the error that occurred.
	ErrorDescription string `json:"error_description"`
}

// AccessTokenResponse defines model for AccessTokenResponse.
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

// ContractLanguage defines model for ContractLanguage.
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

// ContractType defines model for ContractType.
type ContractType string

// ContractVersion defines model for ContractVersion.
type ContractVersion string

// CreateAccessTokenRequest defines model for CreateAccessTokenRequest.
type CreateAccessTokenRequest struct {

	// Base64 encoded JWT following rfc7523 and the Nuts documentation
	Assertion string `json:"assertion"`

	// always must contain the value "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantType string `json:"grant_type"`
}

// CreateJwtBearerTokenRequest defines model for CreateJwtBearerTokenRequest.
type CreateJwtBearerTokenRequest struct {
	Actor     string `json:"actor"`
	Custodian string `json:"custodian"`

	// Base64 encoded IRMA contract conaining the identity of the performer
	Identity string `json:"identity"`

	// The service for which this access-token can be used. The right ouath endpoint is selected based on the service.
	Service string  `json:"service"`
	Subject *string `json:"subject,omitempty"`
}

// CreateSignSessionRequest defines model for CreateSignSessionRequest.
type CreateSignSessionRequest struct {
	Means string `json:"means"`

	// Params are passed to the means. Should be documented in the means documentation.
	Params map[string]interface{} `json:"params"`

	// Base64 encoded payload what needs to be signed.
	Payload string `json:"payload"`
}

// CreateSignSessionResponse defines model for CreateSignSessionResponse.
type CreateSignSessionResponse struct {

	// The means this session uses to sign.
	Means string `json:"means"`

	// Unique identifier of this sign session.
	SessionID string `json:"sessionID"`

	// A pointer to a sign session. This is an opaque value which only has meaning in the context of the signing means. Can be an URL, base64 encoded image of a QRCode etc.
	SessionPtr map[string]interface{} `json:"sessionPtr"`
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

// GetSignSessionStatusResponse defines model for GetSignSessionStatusResponse.
type GetSignSessionStatusResponse struct {

	// Status indicates the status of the signing proces. Values depend on the implementation of the signing means.
	Status string `json:"status"`

	// If the signature session is completed, this property contains the signature embedded in an w3c verifiable presentation.
	VerifiablePresentation *VerifiablePresentation `json:"verifiablePresentation,omitempty"`
}

// JwtBearerTokenResponse defines model for JwtBearerTokenResponse.
type JwtBearerTokenResponse struct {

	// The URL that corresponds to the oauth endpoint of the selected service.
	AuthorizationServerEndpoint string `json:"authorization_server_endpoint"`
	BearerToken                 string `json:"bearer_token"`
}

// LegalEntity defines model for LegalEntity.
type LegalEntity string

// SignatureVerificationRequest defines model for SignatureVerificationRequest.
type SignatureVerificationRequest struct {

	// If the signature session is completed, this property contains the signature embedded in an w3c verifiable presentation.
	VerifiablePresentation VerifiablePresentation `json:"VerifiablePresentation"`

	// Moment in time to check the validity of the signature. If omitted, the current time is used.
	CheckTime *string `json:"checkTime,omitempty"`
}

// SignatureVerificationResponse defines model for SignatureVerificationResponse.
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

// TokenIntrospectionRequest defines model for TokenIntrospectionRequest.
type TokenIntrospectionRequest struct {
	Token string `json:"token"`
}

// TokenIntrospectionResponse defines model for TokenIntrospectionResponse.
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
	Prefix *string `json:"prefix,omitempty"`
	Scope  *string `json:"scope,omitempty"`

	// The Nuts subject id, patient identifier in the form of an oid encoded BSN.
	Sid *string `json:"sid,omitempty"`

	// The subject is always the acting party, thus the care organization requesting access to data.
	Sub *string `json:"sub,omitempty"`

	// Jwt encoded user identity.
	Usi *string `json:"usi,omitempty"`
}

// VerifiablePresentation defines model for VerifiablePresentation.
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
type CreateSignSessionJSONBody CreateSignSessionRequest

// VerifySignatureJSONBody defines parameters for VerifySignature.
type VerifySignatureJSONBody SignatureVerificationRequest

// CreateAccessTokenJSONBody defines parameters for CreateAccessToken.
type CreateAccessTokenJSONBody CreateAccessTokenRequest

// CreateAccessTokenParams defines parameters for CreateAccessToken.
type CreateAccessTokenParams struct {
	XSslClientCert   string  `json:"X-Ssl-Client-Cert"`
	XNutsLegalEntity *string `json:"X-Nuts-LegalEntity,omitempty"`
}

// GetContractByTypeParams defines parameters for GetContractByType.
type GetContractByTypeParams struct {

	// The version of this contract. If omitted, the most recent version will be returned
	Version  *string `json:"version,omitempty"`
	Language *string `json:"language,omitempty"`
}

// CreateJwtBearerTokenRequestBody defines body for CreateJwtBearerToken for application/json ContentType.
type CreateJwtBearerTokenJSONRequestBody CreateJwtBearerTokenJSONBody

// DrawUpContractRequestBody defines body for DrawUpContract for application/json ContentType.
type DrawUpContractJSONRequestBody DrawUpContractJSONBody

// CreateSignSessionRequestBody defines body for CreateSignSession for application/json ContentType.
type CreateSignSessionJSONRequestBody CreateSignSessionJSONBody

// VerifySignatureRequestBody defines body for VerifySignature for application/json ContentType.
type VerifySignatureJSONRequestBody VerifySignatureJSONBody

// CreateAccessTokenRequestBody defines body for CreateAccessToken for application/json ContentType.
type CreateAccessTokenJSONRequestBody CreateAccessTokenJSONBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Introspection endpoint to retrieve information from an Access Token as described by RFC7662
	// (POST /internal/auth/v1/accesstoken/introspect)
	IntrospectAccessToken(ctx echo.Context) error
	// Verifies the access token given in the Authorization header (as bearer token). If it's a valid access token issued by this server, it'll return a 200 status code.
	// If it cannot be verified it'll return 403. Note that it'll not return the contents of the access token. The introspection API is for that.
	// (HEAD /internal/auth/v1/accesstoken/verify)
	VerifyAccessToken(ctx echo.Context, params VerifyAccessTokenParams) error
	// Create a JWT Bearer Token which can be used in the createAccessToken request in the assertion field
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
	// This endpoint must be available to the outside world for other applications to request access tokens.
	// It requires a two-way TLS connection. The client certificate must be a sibling of the signing certificate of the given JWT.
	// The client certificate must be passed using a X-Ssl-Client-Cert header, PEM encoded and urlescaped.
	// (POST /public/auth/v1/accesstoken)
	CreateAccessToken(ctx echo.Context, params CreateAccessTokenParams) error
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

		err = runtime.BindStyledParameter("simple", false, "Authorization", valueList[0], &Authorization)
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

	err = runtime.BindStyledParameter("simple", false, "sessionID", ctx.Param("sessionID"), &sessionID)
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

	// Parameter object where we will unmarshal all parameters from the context
	var params CreateAccessTokenParams

	headers := ctx.Request().Header
	// ------------- Required header parameter "X-Ssl-Client-Cert" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Ssl-Client-Cert")]; found {
		var XSslClientCert string
		n := len(valueList)
		if n != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Expected one value for X-Ssl-Client-Cert, got %d", n))
		}

		err = runtime.BindStyledParameter("simple", false, "X-Ssl-Client-Cert", valueList[0], &XSslClientCert)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter X-Ssl-Client-Cert: %s", err))
		}

		params.XSslClientCert = XSslClientCert
	} else {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Header parameter X-Ssl-Client-Cert is required, but not found"))
	}
	// ------------- Optional header parameter "X-Nuts-LegalEntity" -------------
	if valueList, found := headers[http.CanonicalHeaderKey("X-Nuts-LegalEntity")]; found {
		var XNutsLegalEntity string
		n := len(valueList)
		if n != 1 {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Expected one value for X-Nuts-LegalEntity, got %d", n))
		}

		err = runtime.BindStyledParameter("simple", false, "X-Nuts-LegalEntity", valueList[0], &XNutsLegalEntity)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter X-Nuts-LegalEntity: %s", err))
		}

		params.XNutsLegalEntity = &XNutsLegalEntity
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateAccessToken(ctx, params)
	return err
}

// GetContractByType converts echo context to params.
func (w *ServerInterfaceWrapper) GetContractByType(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "contractType" -------------
	var contractType string

	err = runtime.BindStyledParameter("simple", false, "contractType", ctx.Param("contractType"), &contractType)
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

	router.Add(http.MethodPost, baseURL+"/internal/auth/v1/accesstoken/introspect", wrapper.IntrospectAccessToken)
	router.Add(http.MethodHead, baseURL+"/internal/auth/v1/accesstoken/verify", wrapper.VerifyAccessToken)
	router.Add(http.MethodPost, baseURL+"/internal/auth/v1/bearertoken", wrapper.CreateJwtBearerToken)
	router.Add(http.MethodPut, baseURL+"/internal/auth/v1/contract/drawup", wrapper.DrawUpContract)
	router.Add(http.MethodPost, baseURL+"/internal/auth/v1/signature/session", wrapper.CreateSignSession)
	router.Add(http.MethodGet, baseURL+"/internal/auth/v1/signature/session/:sessionID", wrapper.GetSignSessionStatus)
	router.Add(http.MethodPut, baseURL+"/internal/auth/v1/signature/verify", wrapper.VerifySignature)
	router.Add(http.MethodPost, baseURL+"/public/auth/v1/accesstoken", wrapper.CreateAccessToken)
	router.Add(http.MethodGet, baseURL+"/public/auth/v1/contract/:contractType", wrapper.GetContractByType)

}
