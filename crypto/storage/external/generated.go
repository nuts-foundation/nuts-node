// Package external provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.13.4 DO NOT EDIT.
package external

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
)

// Defines values for ServiceStatusStatus.
const (
	Fail ServiceStatusStatus = "fail"
	Pass ServiceStatusStatus = "pass"
	Warn ServiceStatusStatus = "warn"
)

// ErrorResponse The ErrorResponse contains the Problem Details for HTTP APIs as specified in [RFC7807](https://tools.ietf.org/html/rfc7807).
//
// It provides more details about problems occurred in the storage server.
//
// Return values contain the following members:
// - **title** (string) - A short, human-readable summary of the problem type.
// - **status** (number) - The HTTP status code generated by the origin server for this occurrence of the problem.
// - **backend** (string) The name of the storage backend. This can provide context to the error.
// - **detail** (string) - A human-readable explanation specific to this occurrence of the problem.
type ErrorResponse struct {
	// Backend The name of the storage backend. This can provide context to the error.
	Backend string `json:"backend"`

	// Detail A human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail"`

	// Status HTTP status-code
	Status int `json:"status"`

	// Title A short, human-readable summary of the problem type.
	Title string `json:"title"`
}

// Key The key under which secrets can be stored or retrieved.
//
// The key should be considered opaque and no assumptions should be made about its value or format.
// Note: When the key is used in the URL path, symbols such as slashes and hash symbols must be escaped.
type Key = string

// KeyList List of keys currently stored in the store.
// Note: Keys will be in unescaped form. No assumptions should be made about the order of the keys.
type KeyList = []Key

// Secret The secret value stored under the provided key.
type Secret = string

// SecretResponse Response object containing the secret value.
type SecretResponse struct {
	// Secret The secret value stored under the provided key.
	Secret Secret `json:"secret"`
}

// ServiceStatus Response for the health check endpoint.
type ServiceStatus struct {
	// Details Additional details about the service status.
	Details *string `json:"details,omitempty"`

	// Status Indicates whether the service status is acceptable. Possible values are:
	// * **pass**: healthy.
	// * **fail**: unhealthy.
	// * **warn**: healthy, with some concerns.
	Status ServiceStatusStatus `json:"status"`
}

// ServiceStatusStatus Indicates whether the service status is acceptable. Possible values are:
// * **pass**: healthy.
// * **fail**: unhealthy.
// * **warn**: healthy, with some concerns.
type ServiceStatusStatus string

// StoreSecretRequest Request body to store a secret value. The secret value must not be empty.
type StoreSecretRequest struct {
	// Secret The secret value stored under the provided key.
	Secret Secret `json:"secret"`
}

// StoreSecretJSONRequestBody defines body for StoreSecret for application/json ContentType.
type StoreSecretJSONRequestBody = StoreSecretRequest

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
	// HealthCheck request
	HealthCheck(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// ListKeys request
	ListKeys(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// DeleteSecret request
	DeleteSecret(ctx context.Context, key Key, reqEditors ...RequestEditorFn) (*http.Response, error)

	// LookupSecret request
	LookupSecret(ctx context.Context, key Key, reqEditors ...RequestEditorFn) (*http.Response, error)

	// StoreSecretWithBody request with any body
	StoreSecretWithBody(ctx context.Context, key Key, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	StoreSecret(ctx context.Context, key Key, body StoreSecretJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) HealthCheck(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewHealthCheckRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ListKeys(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewListKeysRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) DeleteSecret(ctx context.Context, key Key, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewDeleteSecretRequest(c.Server, key)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) LookupSecret(ctx context.Context, key Key, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewLookupSecretRequest(c.Server, key)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) StoreSecretWithBody(ctx context.Context, key Key, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewStoreSecretRequestWithBody(c.Server, key, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) StoreSecret(ctx context.Context, key Key, body StoreSecretJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewStoreSecretRequest(c.Server, key, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewHealthCheckRequest generates requests for HealthCheck
func NewHealthCheckRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/health")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewListKeysRequest generates requests for ListKeys
func NewListKeysRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/secrets")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewDeleteSecretRequest generates requests for DeleteSecret
func NewDeleteSecretRequest(server string, key Key) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "key", runtime.ParamLocationPath, key)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/secrets/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("DELETE", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewLookupSecretRequest generates requests for LookupSecret
func NewLookupSecretRequest(server string, key Key) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "key", runtime.ParamLocationPath, key)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/secrets/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewStoreSecretRequest calls the generic StoreSecret builder with application/json body
func NewStoreSecretRequest(server string, key Key, body StoreSecretJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewStoreSecretRequestWithBody(server, key, "application/json", bodyReader)
}

// NewStoreSecretRequestWithBody generates requests for StoreSecret with any type of body
func NewStoreSecretRequestWithBody(server string, key Key, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "key", runtime.ParamLocationPath, key)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/secrets/%s", pathParam0)
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
	// HealthCheckWithResponse request
	HealthCheckWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*HealthCheckResponse, error)

	// ListKeysWithResponse request
	ListKeysWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*ListKeysResponse, error)

	// DeleteSecretWithResponse request
	DeleteSecretWithResponse(ctx context.Context, key Key, reqEditors ...RequestEditorFn) (*DeleteSecretResponse, error)

	// LookupSecretWithResponse request
	LookupSecretWithResponse(ctx context.Context, key Key, reqEditors ...RequestEditorFn) (*LookupSecretResponse, error)

	// StoreSecretWithBodyWithResponse request with any body
	StoreSecretWithBodyWithResponse(ctx context.Context, key Key, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*StoreSecretResponse, error)

	StoreSecretWithResponse(ctx context.Context, key Key, body StoreSecretJSONRequestBody, reqEditors ...RequestEditorFn) (*StoreSecretResponse, error)
}

type HealthCheckResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *ServiceStatus
	JSON503      *ServiceStatus
}

// Status returns HTTPResponse.Status
func (r HealthCheckResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r HealthCheckResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ListKeysResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *KeyList
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r ListKeysResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ListKeysResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type DeleteSecretResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON404      *ErrorResponse
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r DeleteSecretResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r DeleteSecretResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type LookupSecretResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *SecretResponse
	JSON404      *ErrorResponse
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r LookupSecretResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r LookupSecretResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type StoreSecretResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *SecretResponse
	JSON400      *ErrorResponse
	JSON409      *ErrorResponse
	JSON500      *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r StoreSecretResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r StoreSecretResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// HealthCheckWithResponse request returning *HealthCheckResponse
func (c *ClientWithResponses) HealthCheckWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*HealthCheckResponse, error) {
	rsp, err := c.HealthCheck(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseHealthCheckResponse(rsp)
}

// ListKeysWithResponse request returning *ListKeysResponse
func (c *ClientWithResponses) ListKeysWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*ListKeysResponse, error) {
	rsp, err := c.ListKeys(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseListKeysResponse(rsp)
}

// DeleteSecretWithResponse request returning *DeleteSecretResponse
func (c *ClientWithResponses) DeleteSecretWithResponse(ctx context.Context, key Key, reqEditors ...RequestEditorFn) (*DeleteSecretResponse, error) {
	rsp, err := c.DeleteSecret(ctx, key, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseDeleteSecretResponse(rsp)
}

// LookupSecretWithResponse request returning *LookupSecretResponse
func (c *ClientWithResponses) LookupSecretWithResponse(ctx context.Context, key Key, reqEditors ...RequestEditorFn) (*LookupSecretResponse, error) {
	rsp, err := c.LookupSecret(ctx, key, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseLookupSecretResponse(rsp)
}

// StoreSecretWithBodyWithResponse request with arbitrary body returning *StoreSecretResponse
func (c *ClientWithResponses) StoreSecretWithBodyWithResponse(ctx context.Context, key Key, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*StoreSecretResponse, error) {
	rsp, err := c.StoreSecretWithBody(ctx, key, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseStoreSecretResponse(rsp)
}

func (c *ClientWithResponses) StoreSecretWithResponse(ctx context.Context, key Key, body StoreSecretJSONRequestBody, reqEditors ...RequestEditorFn) (*StoreSecretResponse, error) {
	rsp, err := c.StoreSecret(ctx, key, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseStoreSecretResponse(rsp)
}

// ParseHealthCheckResponse parses an HTTP response from a HealthCheckWithResponse call
func ParseHealthCheckResponse(rsp *http.Response) (*HealthCheckResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &HealthCheckResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest ServiceStatus
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 503:
		var dest ServiceStatus
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON503 = &dest

	}

	return response, nil
}

// ParseListKeysResponse parses an HTTP response from a ListKeysWithResponse call
func ParseListKeysResponse(rsp *http.Response) (*ListKeysResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &ListKeysResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest KeyList
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseDeleteSecretResponse parses an HTTP response from a DeleteSecretWithResponse call
func ParseDeleteSecretResponse(rsp *http.Response) (*DeleteSecretResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &DeleteSecretResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 404:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON404 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseLookupSecretResponse parses an HTTP response from a LookupSecretWithResponse call
func ParseLookupSecretResponse(rsp *http.Response) (*LookupSecretResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &LookupSecretResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest SecretResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 404:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON404 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseStoreSecretResponse parses an HTTP response from a StoreSecretWithResponse call
func ParseStoreSecretResponse(rsp *http.Response) (*StoreSecretResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &StoreSecretResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest SecretResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 409:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON409 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}
