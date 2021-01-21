// Package v1 provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen DO NOT EDIT.
package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
)

// DIDResolutionResult defines model for DIDResolutionResult.
type DIDResolutionResult struct {

	// The actual DID Document according to the w3c spec.
	Document DIDDocument `json:"document"`

	// The DID Document metadata.
	DocumentMetadata DIDDocumentMetadata `json:"documentMetadata"`
}

// DIDUpdateRequest defines model for DIDUpdateRequest.
type DIDUpdateRequest struct {

	// hex encoded hash
	CurrentHash string `json:"currentHash"`

	// The actual DID Document according to the w3c spec.
	Document DIDDocument `json:"document"`
}

// UpdateDIDJSONBody defines parameters for UpdateDID.
type UpdateDIDJSONBody DIDUpdateRequest

// UpdateDIDRequestBody defines body for UpdateDID for application/json ContentType.
type UpdateDIDJSONRequestBody UpdateDIDJSONBody

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

	// A callback for modifying requests which are generated before sending over
	// the network.
	RequestEditor RequestEditorFn
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
		client.Client = http.DefaultClient
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
		c.RequestEditor = fn
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// CreateDID request
	CreateDID(ctx context.Context) (*http.Response, error)

	// GetDID request
	GetDID(ctx context.Context, did string) (*http.Response, error)

	// UpdateDID request  with any body
	UpdateDIDWithBody(ctx context.Context, did string, contentType string, body io.Reader) (*http.Response, error)

	UpdateDID(ctx context.Context, did string, body UpdateDIDJSONRequestBody) (*http.Response, error)
}

func (c *Client) CreateDID(ctx context.Context) (*http.Response, error) {
	req, err := NewCreateDIDRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if c.RequestEditor != nil {
		err = c.RequestEditor(ctx, req)
		if err != nil {
			return nil, err
		}
	}
	return c.Client.Do(req)
}

func (c *Client) GetDID(ctx context.Context, did string) (*http.Response, error) {
	req, err := NewGetDIDRequest(c.Server, did)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if c.RequestEditor != nil {
		err = c.RequestEditor(ctx, req)
		if err != nil {
			return nil, err
		}
	}
	return c.Client.Do(req)
}

func (c *Client) UpdateDIDWithBody(ctx context.Context, did string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := NewUpdateDIDRequestWithBody(c.Server, did, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if c.RequestEditor != nil {
		err = c.RequestEditor(ctx, req)
		if err != nil {
			return nil, err
		}
	}
	return c.Client.Do(req)
}

func (c *Client) UpdateDID(ctx context.Context, did string, body UpdateDIDJSONRequestBody) (*http.Response, error) {
	req, err := NewUpdateDIDRequest(c.Server, did, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if c.RequestEditor != nil {
		err = c.RequestEditor(ctx, req)
		if err != nil {
			return nil, err
		}
	}
	return c.Client.Do(req)
}

// NewCreateDIDRequest generates requests for CreateDID
func NewCreateDIDRequest(server string) (*http.Request, error) {
	var err error

	queryUrl, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	basePath := fmt.Sprintf("/internal/vdr/v1/did")
	if basePath[0] == '/' {
		basePath = basePath[1:]
	}

	queryUrl, err = queryUrl.Parse(basePath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetDIDRequest generates requests for GetDID
func NewGetDIDRequest(server string, did string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParam("simple", false, "did", did)
	if err != nil {
		return nil, err
	}

	queryUrl, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	basePath := fmt.Sprintf("/internal/vdr/v1/did/%s", pathParam0)
	if basePath[0] == '/' {
		basePath = basePath[1:]
	}

	queryUrl, err = queryUrl.Parse(basePath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryUrl.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewUpdateDIDRequest calls the generic UpdateDID builder with application/json body
func NewUpdateDIDRequest(server string, did string, body UpdateDIDJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewUpdateDIDRequestWithBody(server, did, "application/json", bodyReader)
}

// NewUpdateDIDRequestWithBody generates requests for UpdateDID with any type of body
func NewUpdateDIDRequestWithBody(server string, did string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParam("simple", false, "did", did)
	if err != nil {
		return nil, err
	}

	queryUrl, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	basePath := fmt.Sprintf("/internal/vdr/v1/did/%s", pathParam0)
	if basePath[0] == '/' {
		basePath = basePath[1:]
	}

	queryUrl, err = queryUrl.Parse(basePath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", queryUrl.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	return req, nil
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
	// CreateDID request
	CreateDIDWithResponse(ctx context.Context) (*CreateDIDResponse, error)

	// GetDID request
	GetDIDWithResponse(ctx context.Context, did string) (*GetDIDResponse, error)

	// UpdateDID request  with any body
	UpdateDIDWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader) (*UpdateDIDResponse, error)

	UpdateDIDWithResponse(ctx context.Context, did string, body UpdateDIDJSONRequestBody) (*UpdateDIDResponse, error)
}

type CreateDIDResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r CreateDIDResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r CreateDIDResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetDIDResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r GetDIDResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetDIDResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type UpdateDIDResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r UpdateDIDResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r UpdateDIDResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// CreateDIDWithResponse request returning *CreateDIDResponse
func (c *ClientWithResponses) CreateDIDWithResponse(ctx context.Context) (*CreateDIDResponse, error) {
	rsp, err := c.CreateDID(ctx)
	if err != nil {
		return nil, err
	}
	return ParseCreateDIDResponse(rsp)
}

// GetDIDWithResponse request returning *GetDIDResponse
func (c *ClientWithResponses) GetDIDWithResponse(ctx context.Context, did string) (*GetDIDResponse, error) {
	rsp, err := c.GetDID(ctx, did)
	if err != nil {
		return nil, err
	}
	return ParseGetDIDResponse(rsp)
}

// UpdateDIDWithBodyWithResponse request with arbitrary body returning *UpdateDIDResponse
func (c *ClientWithResponses) UpdateDIDWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader) (*UpdateDIDResponse, error) {
	rsp, err := c.UpdateDIDWithBody(ctx, did, contentType, body)
	if err != nil {
		return nil, err
	}
	return ParseUpdateDIDResponse(rsp)
}

func (c *ClientWithResponses) UpdateDIDWithResponse(ctx context.Context, did string, body UpdateDIDJSONRequestBody) (*UpdateDIDResponse, error) {
	rsp, err := c.UpdateDID(ctx, did, body)
	if err != nil {
		return nil, err
	}
	return ParseUpdateDIDResponse(rsp)
}

// ParseCreateDIDResponse parses an HTTP response from a CreateDIDWithResponse call
func ParseCreateDIDResponse(rsp *http.Response) (*CreateDIDResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &CreateDIDResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ParseGetDIDResponse parses an HTTP response from a GetDIDWithResponse call
func ParseGetDIDResponse(rsp *http.Response) (*GetDIDResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &GetDIDResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ParseUpdateDIDResponse parses an HTTP response from a UpdateDIDWithResponse call
func ParseUpdateDIDResponse(rsp *http.Response) (*UpdateDIDResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &UpdateDIDResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Creates a new Nuts DID
	// (POST /internal/vdr/v1/did)
	CreateDID(ctx echo.Context) error
	// Resolves a Nuts DID Document
	// (GET /internal/vdr/v1/did/{did})
	GetDID(ctx echo.Context, did string) error
	// Updates a Nuts DID Document
	// (PUT /internal/vdr/v1/did/{did})
	UpdateDID(ctx echo.Context, did string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// CreateDID converts echo context to params.
func (w *ServerInterfaceWrapper) CreateDID(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.CreateDID(ctx)
	return err
}

// GetDID converts echo context to params.
func (w *ServerInterfaceWrapper) GetDID(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameter("simple", false, "did", ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetDID(ctx, did)
	return err
}

// UpdateDID converts echo context to params.
func (w *ServerInterfaceWrapper) UpdateDID(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameter("simple", false, "did", ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.UpdateDID(ctx, did)
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

	router.POST(baseURL+"/internal/vdr/v1/did", wrapper.CreateDID)
	router.GET(baseURL+"/internal/vdr/v1/did/:did", wrapper.GetDID)
	router.PUT(baseURL+"/internal/vdr/v1/did/:did", wrapper.UpdateDID)

}

