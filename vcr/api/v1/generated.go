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

// KeyValuePair defines model for KeyValuePair.
type KeyValuePair struct {

	// Fields from VCs to search on. Concept specific keys must be prepended with the concept name and a '.'. Default fields like: issuer, subject, type do not require a prefix since they are a mandatory part of each VC.
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SearchRequest defines model for SearchRequest.
type SearchRequest struct {

	// limit number of return values to x, default 10
	Limit *float32 `json:"limit,omitempty"`

	// skips first x results, default 0
	Offset *float32 `json:"offset,omitempty"`

	// key/value pairs
	Params []KeyValuePair `json:"params"`
}

// CreateJSONBody defines parameters for Create.
type CreateJSONBody struct {

	// Subject of a Verifiable Credential identifying the holder and expressing claims.
	CredentialSubject *CredentialSubject `json:"credentialSubject,omitempty"`

	// rfc3339 time string until when the credential is valid.
	ExpirationDate *string `json:"expirationDate,omitempty"`

	// DID according to Nuts specification.
	Issuer *string `json:"issuer,omitempty"`

	// List of type definitions for the credential.
	Type *[]string `json:"type,omitempty"`
}

// SearchJSONBody defines parameters for Search.
type SearchJSONBody SearchRequest

// CreateRequestBody defines body for Create for application/json ContentType.
type CreateJSONRequestBody CreateJSONBody

// SearchRequestBody defines body for Search for application/json ContentType.
type SearchJSONRequestBody SearchJSONBody

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
	// Create request  with any body
	CreateWithBody(ctx context.Context, contentType string, body io.Reader) (*http.Response, error)

	Create(ctx context.Context, body CreateJSONRequestBody) (*http.Response, error)

	// Revoke request
	Revoke(ctx context.Context, id string) (*http.Response, error)

	// Resolve request
	Resolve(ctx context.Context, id string) (*http.Response, error)

	// Search request  with any body
	SearchWithBody(ctx context.Context, concept string, contentType string, body io.Reader) (*http.Response, error)

	Search(ctx context.Context, concept string, body SearchJSONRequestBody) (*http.Response, error)
}

func (c *Client) CreateWithBody(ctx context.Context, contentType string, body io.Reader) (*http.Response, error) {
	req, err := NewCreateRequestWithBody(c.Server, contentType, body)
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

func (c *Client) Create(ctx context.Context, body CreateJSONRequestBody) (*http.Response, error) {
	req, err := NewCreateRequest(c.Server, body)
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

func (c *Client) Revoke(ctx context.Context, id string) (*http.Response, error) {
	req, err := NewRevokeRequest(c.Server, id)
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

func (c *Client) Resolve(ctx context.Context, id string) (*http.Response, error) {
	req, err := NewResolveRequest(c.Server, id)
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

func (c *Client) SearchWithBody(ctx context.Context, concept string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := NewSearchRequestWithBody(c.Server, concept, contentType, body)
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

func (c *Client) Search(ctx context.Context, concept string, body SearchJSONRequestBody) (*http.Response, error) {
	req, err := NewSearchRequest(c.Server, concept, body)
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

// NewCreateRequest calls the generic Create builder with application/json body
func NewCreateRequest(server string, body CreateJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewCreateRequestWithBody(server, "application/json", bodyReader)
}

// NewCreateRequestWithBody generates requests for Create with any type of body
func NewCreateRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	queryUrl, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	basePath := fmt.Sprintf("/internal/vcr/v1/vc")
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

// NewRevokeRequest generates requests for Revoke
func NewRevokeRequest(server string, id string) (*http.Request, error) {
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

	basePath := fmt.Sprintf("/internal/vcr/v1/vc/%s", pathParam0)
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

// NewResolveRequest generates requests for Resolve
func NewResolveRequest(server string, id string) (*http.Request, error) {
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

	basePath := fmt.Sprintf("/internal/vcr/v1/vc/%s", pathParam0)
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

// NewSearchRequest calls the generic Search builder with application/json body
func NewSearchRequest(server string, concept string, body SearchJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewSearchRequestWithBody(server, concept, "application/json", bodyReader)
}

// NewSearchRequestWithBody generates requests for Search with any type of body
func NewSearchRequestWithBody(server string, concept string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParam("simple", false, "concept", concept)
	if err != nil {
		return nil, err
	}

	queryUrl, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	basePath := fmt.Sprintf("/internal/vcr/v1/%s", pathParam0)
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
	// Create request  with any body
	CreateWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader) (*CreateResponse, error)

	CreateWithResponse(ctx context.Context, body CreateJSONRequestBody) (*CreateResponse, error)

	// Revoke request
	RevokeWithResponse(ctx context.Context, id string) (*RevokeResponse, error)

	// Resolve request
	ResolveWithResponse(ctx context.Context, id string) (*ResolveResponse, error)

	// Search request  with any body
	SearchWithBodyWithResponse(ctx context.Context, concept string, contentType string, body io.Reader) (*SearchResponse, error)

	SearchWithResponse(ctx context.Context, concept string, body SearchJSONRequestBody) (*SearchResponse, error)
}

type CreateResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r CreateResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r CreateResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type RevokeResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r RevokeResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r RevokeResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ResolveResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r ResolveResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ResolveResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type SearchResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]map[string]interface{}
}

// Status returns HTTPResponse.Status
func (r SearchResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r SearchResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// CreateWithBodyWithResponse request with arbitrary body returning *CreateResponse
func (c *ClientWithResponses) CreateWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader) (*CreateResponse, error) {
	rsp, err := c.CreateWithBody(ctx, contentType, body)
	if err != nil {
		return nil, err
	}
	return ParseCreateResponse(rsp)
}

func (c *ClientWithResponses) CreateWithResponse(ctx context.Context, body CreateJSONRequestBody) (*CreateResponse, error) {
	rsp, err := c.Create(ctx, body)
	if err != nil {
		return nil, err
	}
	return ParseCreateResponse(rsp)
}

// RevokeWithResponse request returning *RevokeResponse
func (c *ClientWithResponses) RevokeWithResponse(ctx context.Context, id string) (*RevokeResponse, error) {
	rsp, err := c.Revoke(ctx, id)
	if err != nil {
		return nil, err
	}
	return ParseRevokeResponse(rsp)
}

// ResolveWithResponse request returning *ResolveResponse
func (c *ClientWithResponses) ResolveWithResponse(ctx context.Context, id string) (*ResolveResponse, error) {
	rsp, err := c.Resolve(ctx, id)
	if err != nil {
		return nil, err
	}
	return ParseResolveResponse(rsp)
}

// SearchWithBodyWithResponse request with arbitrary body returning *SearchResponse
func (c *ClientWithResponses) SearchWithBodyWithResponse(ctx context.Context, concept string, contentType string, body io.Reader) (*SearchResponse, error) {
	rsp, err := c.SearchWithBody(ctx, concept, contentType, body)
	if err != nil {
		return nil, err
	}
	return ParseSearchResponse(rsp)
}

func (c *ClientWithResponses) SearchWithResponse(ctx context.Context, concept string, body SearchJSONRequestBody) (*SearchResponse, error) {
	rsp, err := c.Search(ctx, concept, body)
	if err != nil {
		return nil, err
	}
	return ParseSearchResponse(rsp)
}

// ParseCreateResponse parses an HTTP response from a CreateWithResponse call
func ParseCreateResponse(rsp *http.Response) (*CreateResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &CreateResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ParseRevokeResponse parses an HTTP response from a RevokeWithResponse call
func ParseRevokeResponse(rsp *http.Response) (*RevokeResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &RevokeResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ParseResolveResponse parses an HTTP response from a ResolveWithResponse call
func ParseResolveResponse(rsp *http.Response) (*ResolveResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &ResolveResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ParseSearchResponse parses an HTTP response from a SearchWithResponse call
func ParseSearchResponse(rsp *http.Response) (*SearchResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &SearchResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Creates a new Verifiable Credential
	// (POST /internal/vcr/v1/vc)
	Create(ctx echo.Context) error
	// Revoke a credential
	// (DELETE /internal/vcr/v1/vc/{id})
	Revoke(ctx echo.Context, id string) error
	// Resolves a verifiable credential
	// (GET /internal/vcr/v1/vc/{id})
	Resolve(ctx echo.Context, id string) error
	// Search for a concept. A concept is backed by 1 or more VCs
	// (POST /internal/vcr/v1/{concept})
	Search(ctx echo.Context, concept string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// Create converts echo context to params.
func (w *ServerInterfaceWrapper) Create(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Create(ctx)
	return err
}

// Revoke converts echo context to params.
func (w *ServerInterfaceWrapper) Revoke(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameter("simple", false, "id", ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Revoke(ctx, id)
	return err
}

// Resolve converts echo context to params.
func (w *ServerInterfaceWrapper) Resolve(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameter("simple", false, "id", ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Resolve(ctx, id)
	return err
}

// Search converts echo context to params.
func (w *ServerInterfaceWrapper) Search(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "concept" -------------
	var concept string

	err = runtime.BindStyledParameter("simple", false, "concept", ctx.Param("concept"), &concept)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter concept: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Search(ctx, concept)
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

	router.Add(http.MethodPost, baseURL+"/internal/vcr/v1/vc", wrapper.Create)
	router.Add(http.MethodDelete, baseURL+"/internal/vcr/v1/vc/:id", wrapper.Revoke)
	router.Add(http.MethodGet, baseURL+"/internal/vcr/v1/vc/:id", wrapper.Resolve)
	router.Add(http.MethodPost, baseURL+"/internal/vcr/v1/:concept", wrapper.Search)

}

