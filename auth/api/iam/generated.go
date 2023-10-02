// Package iam provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.15.0 DO NOT EDIT.
package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/oapi-codegen/runtime"
	strictecho "github.com/oapi-codegen/runtime/strictmiddleware/echo"
)

// TokenResponse Token Responses are made as defined in (RFC6749)[https://datatracker.ietf.org/doc/html/rfc6749#section-5.1]
type TokenResponse struct {
	// AccessToken The access token issued by the authorization server.
	AccessToken string `json:"access_token"`

	// ExpiresIn The lifetime in seconds of the access token.
	ExpiresIn *int    `json:"expires_in,omitempty"`
	Scope     *string `json:"scope,omitempty"`

	// TokenType The type of the token issued as described in [RFC6749].
	TokenType string `json:"token_type"`
}

// HandleAuthorizeRequestParams defines parameters for HandleAuthorizeRequest.
type HandleAuthorizeRequestParams struct {
	Params *map[string]string `form:"params,omitempty" json:"params,omitempty"`
}

// HandleTokenRequestFormdataBody defines parameters for HandleTokenRequest.
type HandleTokenRequestFormdataBody struct {
	Code                 string            `form:"code" json:"code"`
	GrantType            string            `form:"grant_type" json:"grant_type"`
	AdditionalProperties map[string]string `json:"-"`
}

// RequestAccessTokenJSONBody defines parameters for RequestAccessToken.
type RequestAccessTokenJSONBody struct {
	// Scope The scope that will be The service for which this access token can be used.
	Scope    string `json:"scope"`
	Verifier string `json:"verifier"`
}

// HandleTokenRequestFormdataRequestBody defines body for HandleTokenRequest for application/x-www-form-urlencoded ContentType.
type HandleTokenRequestFormdataRequestBody HandleTokenRequestFormdataBody

// RequestAccessTokenJSONRequestBody defines body for RequestAccessToken for application/json ContentType.
type RequestAccessTokenJSONRequestBody RequestAccessTokenJSONBody

// Getter for additional properties for HandleTokenRequestFormdataBody. Returns the specified
// element and whether it was found
func (a HandleTokenRequestFormdataBody) Get(fieldName string) (value string, found bool) {
	if a.AdditionalProperties != nil {
		value, found = a.AdditionalProperties[fieldName]
	}
	return
}

// Setter for additional properties for HandleTokenRequestFormdataBody
func (a *HandleTokenRequestFormdataBody) Set(fieldName string, value string) {
	if a.AdditionalProperties == nil {
		a.AdditionalProperties = make(map[string]string)
	}
	a.AdditionalProperties[fieldName] = value
}

// Override default JSON handling for HandleTokenRequestFormdataBody to handle AdditionalProperties
func (a *HandleTokenRequestFormdataBody) UnmarshalJSON(b []byte) error {
	object := make(map[string]json.RawMessage)
	err := json.Unmarshal(b, &object)
	if err != nil {
		return err
	}

	if raw, found := object["code"]; found {
		err = json.Unmarshal(raw, &a.Code)
		if err != nil {
			return fmt.Errorf("error reading 'code': %w", err)
		}
		delete(object, "code")
	}

	if raw, found := object["grant_type"]; found {
		err = json.Unmarshal(raw, &a.GrantType)
		if err != nil {
			return fmt.Errorf("error reading 'grant_type': %w", err)
		}
		delete(object, "grant_type")
	}

	if len(object) != 0 {
		a.AdditionalProperties = make(map[string]string)
		for fieldName, fieldBuf := range object {
			var fieldVal string
			err := json.Unmarshal(fieldBuf, &fieldVal)
			if err != nil {
				return fmt.Errorf("error unmarshaling field %s: %w", fieldName, err)
			}
			a.AdditionalProperties[fieldName] = fieldVal
		}
	}
	return nil
}

// Override default JSON handling for HandleTokenRequestFormdataBody to handle AdditionalProperties
func (a HandleTokenRequestFormdataBody) MarshalJSON() ([]byte, error) {
	var err error
	object := make(map[string]json.RawMessage)

	object["code"], err = json.Marshal(a.Code)
	if err != nil {
		return nil, fmt.Errorf("error marshaling 'code': %w", err)
	}

	object["grant_type"], err = json.Marshal(a.GrantType)
	if err != nil {
		return nil, fmt.Errorf("error marshaling 'grant_type': %w", err)
	}

	for fieldName, field := range a.AdditionalProperties {
		object[fieldName], err = json.Marshal(field)
		if err != nil {
			return nil, fmt.Errorf("error marshaling '%s': %w", fieldName, err)
		}
	}
	return json.Marshal(object)
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Get the OAuth2 Authorization Server metadata
	// (GET /.well-known/oauth-authorization-server/iam/{id})
	OAuthAuthorizationServerMetadata(ctx echo.Context, id string) error
	// Used by resource owners to initiate the authorization code flow.
	// (GET /iam/{id}/authorize)
	HandleAuthorizeRequest(ctx echo.Context, id string, params HandleAuthorizeRequestParams) error
	// Returns the did:web version of a Nuts DID document
	// (GET /iam/{id}/did.json)
	GetWebDID(ctx echo.Context, id string) error
	// Get the OAuth2 Client metadata
	// (GET /iam/{id}/oauth-client)
	OAuthClientMetadata(ctx echo.Context, id string) error
	// Used by to request access- or refresh tokens.
	// (POST /iam/{id}/token)
	HandleTokenRequest(ctx echo.Context, id string) error
	// Requests an access token using the vp_token-bearer grant.
	// (POST /internal/auth/v2/{did}/request-access-token)
	RequestAccessToken(ctx echo.Context, did string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// OAuthAuthorizationServerMetadata converts echo context to params.
func (w *ServerInterfaceWrapper) OAuthAuthorizationServerMetadata(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithLocation("simple", false, "id", runtime.ParamLocationPath, ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.OAuthAuthorizationServerMetadata(ctx, id)
	return err
}

// HandleAuthorizeRequest converts echo context to params.
func (w *ServerInterfaceWrapper) HandleAuthorizeRequest(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithLocation("simple", false, "id", runtime.ParamLocationPath, ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params HandleAuthorizeRequestParams
	// ------------- Optional query parameter "params" -------------

	err = runtime.BindQueryParameter("form", true, false, "params", ctx.QueryParams(), &params.Params)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter params: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.HandleAuthorizeRequest(ctx, id, params)
	return err
}

// GetWebDID converts echo context to params.
func (w *ServerInterfaceWrapper) GetWebDID(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithLocation("simple", false, "id", runtime.ParamLocationPath, ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GetWebDID(ctx, id)
	return err
}

// OAuthClientMetadata converts echo context to params.
func (w *ServerInterfaceWrapper) OAuthClientMetadata(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithLocation("simple", false, "id", runtime.ParamLocationPath, ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.OAuthClientMetadata(ctx, id)
	return err
}

// HandleTokenRequest converts echo context to params.
func (w *ServerInterfaceWrapper) HandleTokenRequest(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithLocation("simple", false, "id", runtime.ParamLocationPath, ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.HandleTokenRequest(ctx, id)
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

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.RequestAccessToken(ctx, did)
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

	router.GET(baseURL+"/.well-known/oauth-authorization-server/iam/:id", wrapper.OAuthAuthorizationServerMetadata)
	router.GET(baseURL+"/iam/:id/authorize", wrapper.HandleAuthorizeRequest)
	router.GET(baseURL+"/iam/:id/did.json", wrapper.GetWebDID)
	router.GET(baseURL+"/iam/:id/oauth-client", wrapper.OAuthClientMetadata)
	router.POST(baseURL+"/iam/:id/token", wrapper.HandleTokenRequest)
	router.POST(baseURL+"/internal/auth/v2/:did/request-access-token", wrapper.RequestAccessToken)

}

type OAuthAuthorizationServerMetadataRequestObject struct {
	Id string `json:"id"`
}

type OAuthAuthorizationServerMetadataResponseObject interface {
	VisitOAuthAuthorizationServerMetadataResponse(w http.ResponseWriter) error
}

type OAuthAuthorizationServerMetadata200JSONResponse OAuthAuthorizationServerMetadata

func (response OAuthAuthorizationServerMetadata200JSONResponse) VisitOAuthAuthorizationServerMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type OAuthAuthorizationServerMetadatadefaultApplicationProblemPlusJSONResponse struct {
	Body struct {
		// Detail A human-readable explanation specific to this occurrence of the problem.
		Detail string `json:"detail"`

		// Status HTTP statuscode
		Status float32 `json:"status"`

		// Title A short, human-readable summary of the problem type.
		Title string `json:"title"`
	}
	StatusCode int
}

func (response OAuthAuthorizationServerMetadatadefaultApplicationProblemPlusJSONResponse) VisitOAuthAuthorizationServerMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type HandleAuthorizeRequestRequestObject struct {
	Id     string `json:"id"`
	Params HandleAuthorizeRequestParams
}

type HandleAuthorizeRequestResponseObject interface {
	VisitHandleAuthorizeRequestResponse(w http.ResponseWriter) error
}

type HandleAuthorizeRequest200TexthtmlResponse struct {
	Body          io.Reader
	ContentLength int64
}

func (response HandleAuthorizeRequest200TexthtmlResponse) VisitHandleAuthorizeRequestResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html")
	if response.ContentLength != 0 {
		w.Header().Set("Content-Length", fmt.Sprint(response.ContentLength))
	}
	w.WriteHeader(200)

	if closer, ok := response.Body.(io.ReadCloser); ok {
		defer closer.Close()
	}
	_, err := io.Copy(w, response.Body)
	return err
}

type HandleAuthorizeRequest302ResponseHeaders struct {
	Location string
}

type HandleAuthorizeRequest302Response struct {
	Headers HandleAuthorizeRequest302ResponseHeaders
}

func (response HandleAuthorizeRequest302Response) VisitHandleAuthorizeRequestResponse(w http.ResponseWriter) error {
	w.Header().Set("Location", fmt.Sprint(response.Headers.Location))
	w.WriteHeader(302)
	return nil
}

type GetWebDIDRequestObject struct {
	Id string `json:"id"`
}

type GetWebDIDResponseObject interface {
	VisitGetWebDIDResponse(w http.ResponseWriter) error
}

type GetWebDID200JSONResponse DIDDocument

func (response GetWebDID200JSONResponse) VisitGetWebDIDResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetWebDID404Response struct {
}

func (response GetWebDID404Response) VisitGetWebDIDResponse(w http.ResponseWriter) error {
	w.WriteHeader(404)
	return nil
}

type OAuthClientMetadataRequestObject struct {
	Id string `json:"id"`
}

type OAuthClientMetadataResponseObject interface {
	VisitOAuthClientMetadataResponse(w http.ResponseWriter) error
}

type OAuthClientMetadata200JSONResponse OAuthClientMetadata

func (response OAuthClientMetadata200JSONResponse) VisitOAuthClientMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type OAuthClientMetadatadefaultApplicationProblemPlusJSONResponse struct {
	Body struct {
		// Detail A human-readable explanation specific to this occurrence of the problem.
		Detail string `json:"detail"`

		// Status HTTP statuscode
		Status float32 `json:"status"`

		// Title A short, human-readable summary of the problem type.
		Title string `json:"title"`
	}
	StatusCode int
}

func (response OAuthClientMetadatadefaultApplicationProblemPlusJSONResponse) VisitOAuthClientMetadataResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type HandleTokenRequestRequestObject struct {
	Id   string `json:"id"`
	Body *HandleTokenRequestFormdataRequestBody
}

type HandleTokenRequestResponseObject interface {
	VisitHandleTokenRequestResponse(w http.ResponseWriter) error
}

type HandleTokenRequest200JSONResponse TokenResponse

func (response HandleTokenRequest200JSONResponse) VisitHandleTokenRequestResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type HandleTokenRequest400JSONResponse ErrorResponse

func (response HandleTokenRequest400JSONResponse) VisitHandleTokenRequestResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type HandleTokenRequest404JSONResponse ErrorResponse

func (response HandleTokenRequest404JSONResponse) VisitHandleTokenRequestResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(404)

	return json.NewEncoder(w).Encode(response)
}

type RequestAccessTokenRequestObject struct {
	Did  string `json:"did"`
	Body *RequestAccessTokenJSONRequestBody
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

type RequestAccessTokendefaultApplicationProblemPlusJSONResponse struct {
	Body struct {
		// Detail A human-readable explanation specific to this occurrence of the problem.
		Detail string `json:"detail"`

		// Status HTTP statuscode
		Status float32 `json:"status"`

		// Title A short, human-readable summary of the problem type.
		Title string `json:"title"`
	}
	StatusCode int
}

func (response RequestAccessTokendefaultApplicationProblemPlusJSONResponse) VisitRequestAccessTokenResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {
	// Get the OAuth2 Authorization Server metadata
	// (GET /.well-known/oauth-authorization-server/iam/{id})
	OAuthAuthorizationServerMetadata(ctx context.Context, request OAuthAuthorizationServerMetadataRequestObject) (OAuthAuthorizationServerMetadataResponseObject, error)
	// Used by resource owners to initiate the authorization code flow.
	// (GET /iam/{id}/authorize)
	HandleAuthorizeRequest(ctx context.Context, request HandleAuthorizeRequestRequestObject) (HandleAuthorizeRequestResponseObject, error)
	// Returns the did:web version of a Nuts DID document
	// (GET /iam/{id}/did.json)
	GetWebDID(ctx context.Context, request GetWebDIDRequestObject) (GetWebDIDResponseObject, error)
	// Get the OAuth2 Client metadata
	// (GET /iam/{id}/oauth-client)
	OAuthClientMetadata(ctx context.Context, request OAuthClientMetadataRequestObject) (OAuthClientMetadataResponseObject, error)
	// Used by to request access- or refresh tokens.
	// (POST /iam/{id}/token)
	HandleTokenRequest(ctx context.Context, request HandleTokenRequestRequestObject) (HandleTokenRequestResponseObject, error)
	// Requests an access token using the vp_token-bearer grant.
	// (POST /internal/auth/v2/{did}/request-access-token)
	RequestAccessToken(ctx context.Context, request RequestAccessTokenRequestObject) (RequestAccessTokenResponseObject, error)
}

type StrictHandlerFunc = strictecho.StrictEchoHandlerFunc
type StrictMiddlewareFunc = strictecho.StrictEchoMiddlewareFunc

func NewStrictHandler(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares}
}

type strictHandler struct {
	ssi         StrictServerInterface
	middlewares []StrictMiddlewareFunc
}

// OAuthAuthorizationServerMetadata operation middleware
func (sh *strictHandler) OAuthAuthorizationServerMetadata(ctx echo.Context, id string) error {
	var request OAuthAuthorizationServerMetadataRequestObject

	request.Id = id

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.OAuthAuthorizationServerMetadata(ctx.Request().Context(), request.(OAuthAuthorizationServerMetadataRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "OAuthAuthorizationServerMetadata")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(OAuthAuthorizationServerMetadataResponseObject); ok {
		return validResponse.VisitOAuthAuthorizationServerMetadataResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// HandleAuthorizeRequest operation middleware
func (sh *strictHandler) HandleAuthorizeRequest(ctx echo.Context, id string, params HandleAuthorizeRequestParams) error {
	var request HandleAuthorizeRequestRequestObject

	request.Id = id
	request.Params = params

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.HandleAuthorizeRequest(ctx.Request().Context(), request.(HandleAuthorizeRequestRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "HandleAuthorizeRequest")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(HandleAuthorizeRequestResponseObject); ok {
		return validResponse.VisitHandleAuthorizeRequestResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// GetWebDID operation middleware
func (sh *strictHandler) GetWebDID(ctx echo.Context, id string) error {
	var request GetWebDIDRequestObject

	request.Id = id

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.GetWebDID(ctx.Request().Context(), request.(GetWebDIDRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetWebDID")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(GetWebDIDResponseObject); ok {
		return validResponse.VisitGetWebDIDResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// OAuthClientMetadata operation middleware
func (sh *strictHandler) OAuthClientMetadata(ctx echo.Context, id string) error {
	var request OAuthClientMetadataRequestObject

	request.Id = id

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.OAuthClientMetadata(ctx.Request().Context(), request.(OAuthClientMetadataRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "OAuthClientMetadata")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(OAuthClientMetadataResponseObject); ok {
		return validResponse.VisitOAuthClientMetadataResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// HandleTokenRequest operation middleware
func (sh *strictHandler) HandleTokenRequest(ctx echo.Context, id string) error {
	var request HandleTokenRequestRequestObject

	request.Id = id

	if form, err := ctx.FormParams(); err == nil {
		var body HandleTokenRequestFormdataRequestBody
		if err := runtime.BindForm(&body, form, nil, nil); err != nil {
			return err
		}
		request.Body = &body
	} else {
		return err
	}

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.HandleTokenRequest(ctx.Request().Context(), request.(HandleTokenRequestRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "HandleTokenRequest")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(HandleTokenRequestResponseObject); ok {
		return validResponse.VisitHandleTokenRequestResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// RequestAccessToken operation middleware
func (sh *strictHandler) RequestAccessToken(ctx echo.Context, did string) error {
	var request RequestAccessTokenRequestObject

	request.Did = did

	var body RequestAccessTokenJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}
	request.Body = &body

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
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}
