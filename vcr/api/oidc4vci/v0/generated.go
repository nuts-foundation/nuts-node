// Package v0 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.13.0 DO NOT EDIT.
package v0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
)

// RequestCredentialParams defines parameters for RequestCredential.
type RequestCredentialParams struct {
	Authorization *string `json:"Authorization,omitempty"`
}

// RequestAccessTokenFormdataBody defines parameters for RequestAccessToken.
type RequestAccessTokenFormdataBody struct {
	GrantType         string `form:"grant_type" json:"grant_type"`
	PreAuthorizedCode string `form:"pre-authorized_code" json:"pre-authorized_code"`
}

// HandleCredentialOfferParams defines parameters for HandleCredentialOffer.
type HandleCredentialOfferParams struct {
	// CredentialOffer Contains the URL encoded credential_offer object (as JSON, see the CredentialOffer component).
	CredentialOffer string `form:"credential_offer" json:"credential_offer"`
}

// RequestCredentialJSONRequestBody defines body for RequestCredential for application/json ContentType.
type RequestCredentialJSONRequestBody = CredentialRequest

// RequestAccessTokenFormdataRequestBody defines body for RequestAccessToken for application/x-www-form-urlencoded ContentType.
type RequestAccessTokenFormdataRequestBody RequestAccessTokenFormdataBody

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Get the OpenID Connect Provider metadata
	// (GET /n2n/identity/{did}/.well-known/oauth-authorization-server)
	GetOIDCProviderMetadata(ctx echo.Context, did string) error
	// Get the OIDC4VCI Credential Issuer Metadata
	// (GET /n2n/identity/{did}/.well-known/openid-credential-issuer)
	GetOIDC4VCIIssuerMetadata(ctx echo.Context, did string) error
	// Get the OAuth2 Client Metadata
	// (GET /n2n/identity/{did}/.well-known/openid-credential-wallet)
	GetOAuth2ClientMetadata(ctx echo.Context, did string) error
	// Used by the wallet to request credentials
	// (POST /n2n/identity/{did}/issuer/oidc4vci/credential)
	RequestCredential(ctx echo.Context, did string, params RequestCredentialParams) error
	// Used by the wallet to request an access token
	// (POST /n2n/identity/{did}/oidc/token)
	RequestAccessToken(ctx echo.Context, did string) error
	// Used by the issuer to offer credentials to the wallet
	// (GET /n2n/identity/{did}/wallet/oidc4vci/credential_offer)
	HandleCredentialOffer(ctx echo.Context, did string, params HandleCredentialOfferParams) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// GetOIDCProviderMetadata converts echo context to params.
func (w *ServerInterfaceWrapper) GetOIDCProviderMetadata(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetOIDCProviderMetadata(ctx, did)
	return err
}

// GetOIDC4VCIIssuerMetadata converts echo context to params.
func (w *ServerInterfaceWrapper) GetOIDC4VCIIssuerMetadata(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetOIDC4VCIIssuerMetadata(ctx, did)
	return err
}

// GetOAuth2ClientMetadata converts echo context to params.
func (w *ServerInterfaceWrapper) GetOAuth2ClientMetadata(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetOAuth2ClientMetadata(ctx, did)
	return err
}

// RequestCredential converts echo context to params.
func (w *ServerInterfaceWrapper) RequestCredential(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params RequestCredentialParams

	headers := ctx.Request().Header
	// ------------- Optional header parameter "Authorization" -------------
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

		params.Authorization = &Authorization
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.RequestCredential(ctx, did, params)
	return err
}

// RequestAccessToken converts echo context to params.
func (w *ServerInterfaceWrapper) RequestAccessToken(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.RequestAccessToken(ctx, did)
	return err
}

// HandleCredentialOffer converts echo context to params.
func (w *ServerInterfaceWrapper) HandleCredentialOffer(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params HandleCredentialOfferParams
	// ------------- Required query parameter "credential_offer" -------------

	err = runtime.BindQueryParameter("form", true, true, "credential_offer", ctx.QueryParams(), &params.CredentialOffer)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter credential_offer: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.HandleCredentialOffer(ctx, did, params)
	return err
}

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

	router.GET(baseURL+"/n2n/identity/:did/.well-known/oauth-authorization-server", wrapper.GetOIDCProviderMetadata)
	router.GET(baseURL+"/n2n/identity/:did/.well-known/openid-credential-issuer", wrapper.GetOIDC4VCIIssuerMetadata)
	router.GET(baseURL+"/n2n/identity/:did/.well-known/openid-credential-wallet", wrapper.GetOAuth2ClientMetadata)
	router.POST(baseURL+"/n2n/identity/:did/issuer/oidc4vci/credential", wrapper.RequestCredential)
	router.POST(baseURL+"/n2n/identity/:did/oidc/token", wrapper.RequestAccessToken)
	router.GET(baseURL+"/n2n/identity/:did/wallet/oidc4vci/credential_offer", wrapper.HandleCredentialOffer)

}

type GetOIDCProviderMetadataRequestObject struct {
	Did string `json:"did"`
}

type GetOIDCProviderMetadataResponseObject interface {
	VisitGetOIDCProviderMetadataResponse(w http.ResponseWriter) error
}

type GetOIDCProviderMetadata200JSONResponse ProviderMetadata

func (response GetOIDCProviderMetadata200JSONResponse) VisitGetOIDCProviderMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetOIDCProviderMetadata404JSONResponse ErrorResponse

func (response GetOIDCProviderMetadata404JSONResponse) VisitGetOIDCProviderMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

type GetOIDC4VCIIssuerMetadataRequestObject struct {
	Did string `json:"did"`
}

type GetOIDC4VCIIssuerMetadataResponseObject interface {
	VisitGetOIDC4VCIIssuerMetadataResponse(w http.ResponseWriter) error
}

type GetOIDC4VCIIssuerMetadata200JSONResponse CredentialIssuerMetadata

func (response GetOIDC4VCIIssuerMetadata200JSONResponse) VisitGetOIDC4VCIIssuerMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetOIDC4VCIIssuerMetadata404JSONResponse ErrorResponse

func (response GetOIDC4VCIIssuerMetadata404JSONResponse) VisitGetOIDC4VCIIssuerMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

type GetOAuth2ClientMetadataRequestObject struct {
	Did string `json:"did"`
}

type GetOAuth2ClientMetadataResponseObject interface {
	VisitGetOAuth2ClientMetadataResponse(w http.ResponseWriter) error
}

type GetOAuth2ClientMetadata200JSONResponse OAuth2ClientMetadata

func (response GetOAuth2ClientMetadata200JSONResponse) VisitGetOAuth2ClientMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetOAuth2ClientMetadata404JSONResponse ErrorResponse

func (response GetOAuth2ClientMetadata404JSONResponse) VisitGetOAuth2ClientMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

type RequestCredentialRequestObject struct {
	Did    string `json:"did"`
	Params RequestCredentialParams
	Body   *RequestCredentialJSONRequestBody
}

type RequestCredentialResponseObject interface {
	VisitRequestCredentialResponse(w http.ResponseWriter) error
}

type RequestCredential200JSONResponse CredentialResponse

func (response RequestCredential200JSONResponse) VisitRequestCredentialResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type RequestCredential400JSONResponse ErrorResponse

func (response RequestCredential400JSONResponse) VisitRequestCredentialResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type RequestCredential401JSONResponse ErrorResponse

func (response RequestCredential401JSONResponse) VisitRequestCredentialResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(401)

	return json.NewEncoder(w).Encode(response)
}

type RequestCredential403JSONResponse ErrorResponse

func (response RequestCredential403JSONResponse) VisitRequestCredentialResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(403)

	return json.NewEncoder(w).Encode(response)
}

type RequestCredential404JSONResponse ErrorResponse

func (response RequestCredential404JSONResponse) VisitRequestCredentialResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

type RequestAccessTokenRequestObject struct {
	Did  string `json:"did"`
	Body *RequestAccessTokenFormdataRequestBody
}

type RequestAccessTokenResponseObject interface {
	VisitRequestAccessTokenResponse(w http.ResponseWriter) error
}

type RequestAccessToken200JSONResponse TokenResponse

func (response RequestAccessToken200JSONResponse) VisitRequestAccessTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type RequestAccessToken400JSONResponse ErrorResponse

func (response RequestAccessToken400JSONResponse) VisitRequestAccessTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type RequestAccessToken404JSONResponse ErrorResponse

func (response RequestAccessToken404JSONResponse) VisitRequestAccessTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

type HandleCredentialOfferRequestObject struct {
	Did    string `json:"did"`
	Params HandleCredentialOfferParams
}

type HandleCredentialOfferResponseObject interface {
	VisitHandleCredentialOfferResponse(w http.ResponseWriter) error
}

type HandleCredentialOffer202TextResponse string

func (response HandleCredentialOffer202TextResponse) VisitHandleCredentialOfferResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(202)

	_, err := w.Write([]byte(response))
	return err
}

type HandleCredentialOffer400JSONResponse ErrorResponse

func (response HandleCredentialOffer400JSONResponse) VisitHandleCredentialOfferResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type HandleCredentialOffer404JSONResponse ErrorResponse

func (response HandleCredentialOffer404JSONResponse) VisitHandleCredentialOfferResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {
	// Get the OpenID Connect Provider metadata
	// (GET /n2n/identity/{did}/.well-known/oauth-authorization-server)
	GetOIDCProviderMetadata(ctx context.Context, request GetOIDCProviderMetadataRequestObject) (GetOIDCProviderMetadataResponseObject, error)
	// Get the OIDC4VCI Credential Issuer Metadata
	// (GET /n2n/identity/{did}/.well-known/openid-credential-issuer)
	GetOIDC4VCIIssuerMetadata(ctx context.Context, request GetOIDC4VCIIssuerMetadataRequestObject) (GetOIDC4VCIIssuerMetadataResponseObject, error)
	// Get the OAuth2 Client Metadata
	// (GET /n2n/identity/{did}/.well-known/openid-credential-wallet)
	GetOAuth2ClientMetadata(ctx context.Context, request GetOAuth2ClientMetadataRequestObject) (GetOAuth2ClientMetadataResponseObject, error)
	// Used by the wallet to request credentials
	// (POST /n2n/identity/{did}/issuer/oidc4vci/credential)
	RequestCredential(ctx context.Context, request RequestCredentialRequestObject) (RequestCredentialResponseObject, error)
	// Used by the wallet to request an access token
	// (POST /n2n/identity/{did}/oidc/token)
	RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error)
	// Used by the issuer to offer credentials to the wallet
	// (GET /n2n/identity/{did}/wallet/oidc4vci/credential_offer)
	HandleCredentialOffer(ctx context.Context, request HandleCredentialOfferRequestObject) (HandleCredentialOfferResponseObject, error)
}

type StrictHandlerFunc = runtime.StrictEchoHandlerFunc
type StrictMiddlewareFunc = runtime.StrictEchoMiddlewareFunc

func NewStrictHandler(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares}
}

type strictHandler struct {
	ssi         StrictServerInterface
	middlewares []StrictMiddlewareFunc
}

// GetOIDCProviderMetadata operation middleware
func (sh *strictHandler) GetOIDCProviderMetadata(ctx echo.Context, did string) error {
	var request GetOIDCProviderMetadataRequestObject

	request.Did = did

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.GetOIDCProviderMetadata(ctx.Request().Context(), request.(GetOIDCProviderMetadataRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetOIDCProviderMetadata")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(GetOIDCProviderMetadataResponseObject); ok {
		return validResponse.VisitGetOIDCProviderMetadataResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("Unexpected response type: %T", response)
	}
	return nil
}

// GetOIDC4VCIIssuerMetadata operation middleware
func (sh *strictHandler) GetOIDC4VCIIssuerMetadata(ctx echo.Context, did string) error {
	var request GetOIDC4VCIIssuerMetadataRequestObject

	request.Did = did

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.GetOIDC4VCIIssuerMetadata(ctx.Request().Context(), request.(GetOIDC4VCIIssuerMetadataRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetOIDC4VCIIssuerMetadata")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(GetOIDC4VCIIssuerMetadataResponseObject); ok {
		return validResponse.VisitGetOIDC4VCIIssuerMetadataResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("Unexpected response type: %T", response)
	}
	return nil
}

// GetOAuth2ClientMetadata operation middleware
func (sh *strictHandler) GetOAuth2ClientMetadata(ctx echo.Context, did string) error {
	var request GetOAuth2ClientMetadataRequestObject

	request.Did = did

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.GetOAuth2ClientMetadata(ctx.Request().Context(), request.(GetOAuth2ClientMetadataRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetOAuth2ClientMetadata")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(GetOAuth2ClientMetadataResponseObject); ok {
		return validResponse.VisitGetOAuth2ClientMetadataResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("Unexpected response type: %T", response)
	}
	return nil
}

// RequestCredential operation middleware
func (sh *strictHandler) RequestCredential(ctx echo.Context, did string, params RequestCredentialParams) error {
	var request RequestCredentialRequestObject

	request.Did = did
	request.Params = params

	var body RequestCredentialJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}
	request.Body = &body

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.RequestCredential(ctx.Request().Context(), request.(RequestCredentialRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "RequestCredential")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(RequestCredentialResponseObject); ok {
		return validResponse.VisitRequestCredentialResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("Unexpected response type: %T", response)
	}
	return nil
}

// RequestAccessToken operation middleware
func (sh *strictHandler) RequestAccessToken(ctx echo.Context, did string) error {
	var request RequestAccessTokenRequestObject

	request.Did = did

	if form, err := ctx.FormParams(); err == nil {
		var body RequestAccessTokenFormdataRequestBody
		if err := runtime.BindForm(&body, form, nil, nil); err != nil {
			return err
		}
		request.Body = &body
	} else {
		return err
	}

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.RequestAccessToken(ctx.Request().Context(), request.(RequestAccessTokenRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "RequestAccessToken")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(RequestAccessTokenResponseObject); ok {
		return validResponse.VisitRequestAccessTokenResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("Unexpected response type: %T", response)
	}
	return nil
}

// HandleCredentialOffer operation middleware
func (sh *strictHandler) HandleCredentialOffer(ctx echo.Context, did string, params HandleCredentialOfferParams) error {
	var request HandleCredentialOfferRequestObject

	request.Did = did
	request.Params = params

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.HandleCredentialOffer(ctx.Request().Context(), request.(HandleCredentialOfferRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "HandleCredentialOffer")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(HandleCredentialOfferResponseObject); ok {
		return validResponse.VisitHandleCredentialOfferResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("Unexpected response type: %T", response)
	}
	return nil
}
