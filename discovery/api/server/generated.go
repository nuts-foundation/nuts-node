// Package server provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/oapi-codegen/runtime"
	strictecho "github.com/oapi-codegen/runtime/strictmiddleware/echo"
)

// SearchResult defines model for SearchResult.
type SearchResult struct {
	// Fields Input descriptor IDs and their mapped values that from the Verifiable Credential.
	Fields map[string]interface{} `json:"fields"`

	// Id The ID of the Verifiable Presentation.
	Id string `json:"id"`

	// SubjectId The ID of the Verifiable Credential subject (holder), typically a DID.
	SubjectId string                 `json:"subject_id"`
	Vp        VerifiablePresentation `json:"vp"`
}

// GetPresentationsParams defines parameters for GetPresentations.
type GetPresentationsParams struct {
	Timestamp *int `form:"timestamp,omitempty" json:"timestamp,omitempty"`
}

// RegisterPresentationJSONRequestBody defines body for RegisterPresentation for application/json ContentType.
type RegisterPresentationJSONRequestBody = VerifiablePresentation

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// GetPresentations request
	GetPresentations(ctx context.Context, serviceID string, params *GetPresentationsParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// RegisterPresentationWithBody request with any body
	RegisterPresentationWithBody(ctx context.Context, serviceID string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	RegisterPresentation(ctx context.Context, serviceID string, body RegisterPresentationJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) GetPresentations(ctx context.Context, serviceID string, params *GetPresentationsParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetPresentationsRequest(c.Server, serviceID, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) RegisterPresentationWithBody(ctx context.Context, serviceID string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewRegisterPresentationRequestWithBody(c.Server, serviceID, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) RegisterPresentation(ctx context.Context, serviceID string, body RegisterPresentationJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewRegisterPresentationRequest(c.Server, serviceID, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewGetPresentationsRequest generates requests for GetPresentations
func NewGetPresentationsRequest(server string, serviceID string, params *GetPresentationsParams) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "serviceID", runtime.ParamLocationPath, serviceID)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/discovery/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if params.Timestamp != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "timestamp", runtime.ParamLocationQuery, *params.Timestamp); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewRegisterPresentationRequest calls the generic RegisterPresentation builder with application/json body
func NewRegisterPresentationRequest(server string, serviceID string, body RegisterPresentationJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewRegisterPresentationRequestWithBody(server, serviceID, "application/json", bodyReader)
}

// NewRegisterPresentationRequestWithBody generates requests for RegisterPresentation with any type of body
func NewRegisterPresentationRequestWithBody(server string, serviceID string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "serviceID", runtime.ParamLocationPath, serviceID)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/discovery/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// GetPresentationsWithResponse request
	GetPresentationsWithResponse(ctx context.Context, serviceID string, params *GetPresentationsParams, reqEditors ...RequestEditorFn) (*GetPresentationsResponse, error)

	// RegisterPresentationWithBodyWithResponse request with any body
	RegisterPresentationWithBodyWithResponse(ctx context.Context, serviceID string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*RegisterPresentationResponse, error)

	RegisterPresentationWithResponse(ctx context.Context, serviceID string, body RegisterPresentationJSONRequestBody, reqEditors ...RequestEditorFn) (*RegisterPresentationResponse, error)
}

type GetPresentationsResponse struct {
	Body                          []byte
	HTTPResponse                  *http.Response
	JSON200                       *PresentationsResponse
	ApplicationproblemJSONDefault *struct {
		// Detail A human-readable explanation specific to this occurrence of the problem.
		Detail string `json:"detail"`

		// Status HTTP statuscode
		Status float32 `json:"status"`

		// Title A short, human-readable summary of the problem type.
		Title string `json:"title"`
	}
}

// Status returns HTTPResponse.Status
func (r GetPresentationsResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetPresentationsResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type RegisterPresentationResponse struct {
	Body                      []byte
	HTTPResponse              *http.Response
	ApplicationproblemJSON400 *struct {
		// Detail A human-readable explanation specific to this occurrence of the problem.
		Detail string `json:"detail"`

		// Status HTTP statuscode
		Status float32 `json:"status"`

		// Title A short, human-readable summary of the problem type.
		Title string `json:"title"`
	}
	ApplicationproblemJSONDefault *struct {
		// Detail A human-readable explanation specific to this occurrence of the problem.
		Detail string `json:"detail"`

		// Status HTTP statuscode
		Status float32 `json:"status"`

		// Title A short, human-readable summary of the problem type.
		Title string `json:"title"`
	}
}

// Status returns HTTPResponse.Status
func (r RegisterPresentationResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r RegisterPresentationResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// GetPresentationsWithResponse request returning *GetPresentationsResponse
func (c *ClientWithResponses) GetPresentationsWithResponse(ctx context.Context, serviceID string, params *GetPresentationsParams, reqEditors ...RequestEditorFn) (*GetPresentationsResponse, error) {
	rsp, err := c.GetPresentations(ctx, serviceID, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetPresentationsResponse(rsp)
}

// RegisterPresentationWithBodyWithResponse request with arbitrary body returning *RegisterPresentationResponse
func (c *ClientWithResponses) RegisterPresentationWithBodyWithResponse(ctx context.Context, serviceID string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*RegisterPresentationResponse, error) {
	rsp, err := c.RegisterPresentationWithBody(ctx, serviceID, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseRegisterPresentationResponse(rsp)
}

func (c *ClientWithResponses) RegisterPresentationWithResponse(ctx context.Context, serviceID string, body RegisterPresentationJSONRequestBody, reqEditors ...RequestEditorFn) (*RegisterPresentationResponse, error) {
	rsp, err := c.RegisterPresentation(ctx, serviceID, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseRegisterPresentationResponse(rsp)
}

// ParseGetPresentationsResponse parses an HTTP response from a GetPresentationsWithResponse call
func ParseGetPresentationsResponse(rsp *http.Response) (*GetPresentationsResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetPresentationsResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest PresentationsResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest struct {
			// Detail A human-readable explanation specific to this occurrence of the problem.
			Detail string `json:"detail"`

			// Status HTTP statuscode
			Status float32 `json:"status"`

			// Title A short, human-readable summary of the problem type.
			Title string `json:"title"`
		}
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationproblemJSONDefault = &dest

	}

	return response, nil
}

// ParseRegisterPresentationResponse parses an HTTP response from a RegisterPresentationWithResponse call
func ParseRegisterPresentationResponse(rsp *http.Response) (*RegisterPresentationResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &RegisterPresentationResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest struct {
			// Detail A human-readable explanation specific to this occurrence of the problem.
			Detail string `json:"detail"`

			// Status HTTP statuscode
			Status float32 `json:"status"`

			// Title A short, human-readable summary of the problem type.
			Title string `json:"title"`
		}
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationproblemJSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest struct {
			// Detail A human-readable explanation specific to this occurrence of the problem.
			Detail string `json:"detail"`

			// Status HTTP statuscode
			Status float32 `json:"status"`

			// Title A short, human-readable summary of the problem type.
			Title string `json:"title"`
		}
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.ApplicationproblemJSONDefault = &dest

	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Retrieves the presentations of a Discovery Service.
	// (GET /discovery/{serviceID})
	GetPresentations(ctx echo.Context, serviceID string, params GetPresentationsParams) error
	// Register a presentation on the Discovery Service.
	// (POST /discovery/{serviceID})
	RegisterPresentation(ctx echo.Context, serviceID string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// GetPresentations converts echo context to params.
func (w *ServerInterfaceWrapper) GetPresentations(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "serviceID" -------------
	var serviceID string

	err = runtime.BindStyledParameterWithOptions("simple", "serviceID", ctx.Param("serviceID"), &serviceID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter serviceID: %s", err))
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params GetPresentationsParams
	// ------------- Optional query parameter "timestamp" -------------

	err = runtime.BindQueryParameter("form", true, false, "timestamp", ctx.QueryParams(), &params.Timestamp)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter timestamp: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GetPresentations(ctx, serviceID, params)
	return err
}

// RegisterPresentation converts echo context to params.
func (w *ServerInterfaceWrapper) RegisterPresentation(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "serviceID" -------------
	var serviceID string

	err = runtime.BindStyledParameterWithOptions("simple", "serviceID", ctx.Param("serviceID"), &serviceID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter serviceID: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.RegisterPresentation(ctx, serviceID)
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

	router.GET(baseURL+"/discovery/:serviceID", wrapper.GetPresentations)
	router.POST(baseURL+"/discovery/:serviceID", wrapper.RegisterPresentation)

}

type GetPresentationsRequestObject struct {
	ServiceID string `json:"serviceID"`
	Params    GetPresentationsParams
}

type GetPresentationsResponseObject interface {
	VisitGetPresentationsResponse(w http.ResponseWriter) error
}

type GetPresentations200JSONResponse PresentationsResponse

func (response GetPresentations200JSONResponse) VisitGetPresentationsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetPresentationsdefaultApplicationProblemPlusJSONResponse struct {
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

func (response GetPresentationsdefaultApplicationProblemPlusJSONResponse) VisitGetPresentationsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type RegisterPresentationRequestObject struct {
	ServiceID string `json:"serviceID"`
	Body      *RegisterPresentationJSONRequestBody
}

type RegisterPresentationResponseObject interface {
	VisitRegisterPresentationResponse(w http.ResponseWriter) error
}

type RegisterPresentation201Response struct {
}

func (response RegisterPresentation201Response) VisitRegisterPresentationResponse(w http.ResponseWriter) error {
	w.WriteHeader(201)
	return nil
}

type RegisterPresentation400ApplicationProblemPlusJSONResponse struct {
	// Detail A human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail"`

	// Status HTTP statuscode
	Status float32 `json:"status"`

	// Title A short, human-readable summary of the problem type.
	Title string `json:"title"`
}

func (response RegisterPresentation400ApplicationProblemPlusJSONResponse) VisitRegisterPresentationResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type RegisterPresentationdefaultApplicationProblemPlusJSONResponse struct {
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

func (response RegisterPresentationdefaultApplicationProblemPlusJSONResponse) VisitRegisterPresentationResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {
	// Retrieves the presentations of a Discovery Service.
	// (GET /discovery/{serviceID})
	GetPresentations(ctx context.Context, request GetPresentationsRequestObject) (GetPresentationsResponseObject, error)
	// Register a presentation on the Discovery Service.
	// (POST /discovery/{serviceID})
	RegisterPresentation(ctx context.Context, request RegisterPresentationRequestObject) (RegisterPresentationResponseObject, error)
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

// GetPresentations operation middleware
func (sh *strictHandler) GetPresentations(ctx echo.Context, serviceID string, params GetPresentationsParams) error {
	var request GetPresentationsRequestObject

	request.ServiceID = serviceID
	request.Params = params

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.GetPresentations(ctx.Request().Context(), request.(GetPresentationsRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetPresentations")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(GetPresentationsResponseObject); ok {
		return validResponse.VisitGetPresentationsResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// RegisterPresentation operation middleware
func (sh *strictHandler) RegisterPresentation(ctx echo.Context, serviceID string) error {
	var request RegisterPresentationRequestObject

	request.ServiceID = serviceID

	var body RegisterPresentationJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}
	request.Body = &body

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.RegisterPresentation(ctx.Request().Context(), request.(RegisterPresentationRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "RegisterPresentation")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(RegisterPresentationResponseObject); ok {
		return validResponse.VisitRegisterPresentationResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}
