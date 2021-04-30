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

// EndpointCreateRequest defines model for EndpointCreateRequest.
type EndpointCreateRequest struct {

	// A URL.
	Endpoint string `json:"endpoint"`

	// type of the endpoint. May be freely choosen.
	Type string `json:"type"`
}

// AddEndpointJSONBody defines parameters for AddEndpoint.
type AddEndpointJSONBody EndpointCreateRequest

// AddEndpointRequestBody defines body for AddEndpoint for application/json ContentType.
type AddEndpointJSONRequestBody AddEndpointJSONBody

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
	// AddEndpoint request  with any body
	AddEndpointWithBody(ctx context.Context, did string, contentType string, body io.Reader) (*http.Response, error)

	AddEndpoint(ctx context.Context, did string, body AddEndpointJSONRequestBody) (*http.Response, error)

	// DeleteEndpoint request
	DeleteEndpoint(ctx context.Context, id string) (*http.Response, error)
}

func (c *Client) AddEndpointWithBody(ctx context.Context, did string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := NewAddEndpointRequestWithBody(c.Server, did, contentType, body)
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

func (c *Client) AddEndpoint(ctx context.Context, did string, body AddEndpointJSONRequestBody) (*http.Response, error) {
	req, err := NewAddEndpointRequest(c.Server, did, body)
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

func (c *Client) DeleteEndpoint(ctx context.Context, id string) (*http.Response, error) {
	req, err := NewDeleteEndpointRequest(c.Server, id)
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

// NewAddEndpointRequest calls the generic AddEndpoint builder with application/json body
func NewAddEndpointRequest(server string, did string, body AddEndpointJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewAddEndpointRequestWithBody(server, did, "application/json", bodyReader)
}

// NewAddEndpointRequestWithBody generates requests for AddEndpoint with any type of body
func NewAddEndpointRequestWithBody(server string, did string, contentType string, body io.Reader) (*http.Request, error) {
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

	basePath := fmt.Sprintf("/internal/didman/v1/did/%s/endpoint", pathParam0)
	if basePath[0] == '/' {
		basePath = basePath[1:]
	}

	queryUrl, err = queryUrl.Parse(basePath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryUrl.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)
	return req, nil
}

// NewDeleteEndpointRequest generates requests for DeleteEndpoint
func NewDeleteEndpointRequest(server string, id string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParam("simple", false, "id", id)
	if err != nil {
		return nil, err
	}

	queryUrl, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	basePath := fmt.Sprintf("/internal/didman/v1/service/%s", pathParam0)
	if basePath[0] == '/' {
		basePath = basePath[1:]
	}

	queryUrl, err = queryUrl.Parse(basePath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("DELETE", queryUrl.String(), nil)
	if err != nil {
		return nil, err
	}

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
	// AddEndpoint request  with any body
	AddEndpointWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader) (*AddEndpointResponse, error)

	AddEndpointWithResponse(ctx context.Context, did string, body AddEndpointJSONRequestBody) (*AddEndpointResponse, error)

	// DeleteEndpoint request
	DeleteEndpointWithResponse(ctx context.Context, id string) (*DeleteEndpointResponse, error)
}

type AddEndpointResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r AddEndpointResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r AddEndpointResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type DeleteEndpointResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r DeleteEndpointResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r DeleteEndpointResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// AddEndpointWithBodyWithResponse request with arbitrary body returning *AddEndpointResponse
func (c *ClientWithResponses) AddEndpointWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader) (*AddEndpointResponse, error) {
	rsp, err := c.AddEndpointWithBody(ctx, did, contentType, body)
	if err != nil {
		return nil, err
	}
	return ParseAddEndpointResponse(rsp)
}

func (c *ClientWithResponses) AddEndpointWithResponse(ctx context.Context, did string, body AddEndpointJSONRequestBody) (*AddEndpointResponse, error) {
	rsp, err := c.AddEndpoint(ctx, did, body)
	if err != nil {
		return nil, err
	}
	return ParseAddEndpointResponse(rsp)
}

// DeleteEndpointWithResponse request returning *DeleteEndpointResponse
func (c *ClientWithResponses) DeleteEndpointWithResponse(ctx context.Context, id string) (*DeleteEndpointResponse, error) {
	rsp, err := c.DeleteEndpoint(ctx, id)
	if err != nil {
		return nil, err
	}
	return ParseDeleteEndpointResponse(rsp)
}

// ParseAddEndpointResponse parses an HTTP response from a AddEndpointWithResponse call
func ParseAddEndpointResponse(rsp *http.Response) (*AddEndpointResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &AddEndpointResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ParseDeleteEndpointResponse parses an HTTP response from a DeleteEndpointWithResponse call
func ParseDeleteEndpointResponse(rsp *http.Response) (*DeleteEndpointResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &DeleteEndpointResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Add a concrete service to a DID Document.
	// (POST /internal/didman/v1/did/{did}/endpoint)
	AddEndpoint(ctx echo.Context, did string) error
	// Remove a service from a DID Document.
	// (DELETE /internal/didman/v1/service/{id})
	DeleteEndpoint(ctx echo.Context, id string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// AddEndpoint converts echo context to params.
func (w *ServerInterfaceWrapper) AddEndpoint(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameter("simple", false, "did", ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.AddEndpoint(ctx, did)
	return err
}

// DeleteEndpoint converts echo context to params.
func (w *ServerInterfaceWrapper) DeleteEndpoint(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameter("simple", false, "id", ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.DeleteEndpoint(ctx, id)
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

	router.Add(http.MethodPost, baseURL+"/internal/didman/v1/did/:did/endpoint", wrapper.AddEndpoint)
	router.Add(http.MethodDelete, baseURL+"/internal/didman/v1/service/:id", wrapper.DeleteEndpoint)

}
