// Package v1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package v1

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
	strictecho "github.com/oapi-codegen/runtime/strictmiddleware/echo"
)

const (
	JwtBearerAuthScopes = "jwtBearerAuth.Scopes"
)

// DecryptJweRequest defines model for DecryptJweRequest.
type DecryptJweRequest struct {
	// Message The message to be decrypted as string in format aa==.bb==.cc==.dd==.ee==
	Message string `json:"message"`
}

// EncryptJweRequest defines model for EncryptJweRequest.
type EncryptJweRequest struct {
	// Headers The map of protected headers.
	// Note: The value of the kid header will be ignored and overwritten by the used receiver KID.
	Headers map[string]interface{} `json:"headers"`

	// Payload The payload to be signed as bytes. The bytes must be encoded with Base64 encoding.
	Payload []byte `json:"payload"`

	// Receiver The DID reference of the message receiver OR the KID of the message receiver.
	Receiver string `json:"receiver"`
}

// SignJwsRequest defines model for SignJwsRequest.
type SignJwsRequest struct {
	// Detached In detached mode the payload is signed but NOT included in the returned JWS object. Instead, the space between the first and second dot is empty, like this: "<header>..<signature>" Defaults to false.
	Detached *bool `json:"detached,omitempty"`

	// Headers The map of protected headers
	Headers map[string]interface{} `json:"headers"`

	// Kid Reference to the key ID used for signing the JWS.
	Kid string `json:"kid"`

	// Payload The payload to be signed as bytes. The bytes must be encoded with Base64 encoding.
	Payload []byte `json:"payload"`
}

// SignJwtRequest defines model for SignJwtRequest.
type SignJwtRequest struct {
	Claims map[string]interface{} `json:"claims"`
	Kid    string                 `json:"kid"`
}

// DecryptJweJSONRequestBody defines body for DecryptJwe for application/json ContentType.
type DecryptJweJSONRequestBody = DecryptJweRequest

// EncryptJweJSONRequestBody defines body for EncryptJwe for application/json ContentType.
type EncryptJweJSONRequestBody = EncryptJweRequest

// SignJwsJSONRequestBody defines body for SignJws for application/json ContentType.
type SignJwsJSONRequestBody = SignJwsRequest

// SignJwtJSONRequestBody defines body for SignJwt for application/json ContentType.
type SignJwtJSONRequestBody = SignJwtRequest

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
	// DecryptJweWithBody request with any body
	DecryptJweWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	DecryptJwe(ctx context.Context, body DecryptJweJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// EncryptJweWithBody request with any body
	EncryptJweWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	EncryptJwe(ctx context.Context, body EncryptJweJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// SignJwsWithBody request with any body
	SignJwsWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	SignJws(ctx context.Context, body SignJwsJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// SignJwtWithBody request with any body
	SignJwtWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	SignJwt(ctx context.Context, body SignJwtJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) DecryptJweWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewDecryptJweRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) DecryptJwe(ctx context.Context, body DecryptJweJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewDecryptJweRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) EncryptJweWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewEncryptJweRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) EncryptJwe(ctx context.Context, body EncryptJweJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewEncryptJweRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) SignJwsWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewSignJwsRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) SignJws(ctx context.Context, body SignJwsJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewSignJwsRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) SignJwtWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewSignJwtRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) SignJwt(ctx context.Context, body SignJwtJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewSignJwtRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewDecryptJweRequest calls the generic DecryptJwe builder with application/json body
func NewDecryptJweRequest(server string, body DecryptJweJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewDecryptJweRequestWithBody(server, "application/json", bodyReader)
}

// NewDecryptJweRequestWithBody generates requests for DecryptJwe with any type of body
func NewDecryptJweRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/crypto/v1/decrypt_jwe")
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

// NewEncryptJweRequest calls the generic EncryptJwe builder with application/json body
func NewEncryptJweRequest(server string, body EncryptJweJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewEncryptJweRequestWithBody(server, "application/json", bodyReader)
}

// NewEncryptJweRequestWithBody generates requests for EncryptJwe with any type of body
func NewEncryptJweRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/crypto/v1/encrypt_jwe")
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

// NewSignJwsRequest calls the generic SignJws builder with application/json body
func NewSignJwsRequest(server string, body SignJwsJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewSignJwsRequestWithBody(server, "application/json", bodyReader)
}

// NewSignJwsRequestWithBody generates requests for SignJws with any type of body
func NewSignJwsRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/crypto/v1/sign_jws")
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

// NewSignJwtRequest calls the generic SignJwt builder with application/json body
func NewSignJwtRequest(server string, body SignJwtJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewSignJwtRequestWithBody(server, "application/json", bodyReader)
}

// NewSignJwtRequestWithBody generates requests for SignJwt with any type of body
func NewSignJwtRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/crypto/v1/sign_jwt")
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
	// DecryptJweWithBodyWithResponse request with any body
	DecryptJweWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*DecryptJweResponse, error)

	DecryptJweWithResponse(ctx context.Context, body DecryptJweJSONRequestBody, reqEditors ...RequestEditorFn) (*DecryptJweResponse, error)

	// EncryptJweWithBodyWithResponse request with any body
	EncryptJweWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*EncryptJweResponse, error)

	EncryptJweWithResponse(ctx context.Context, body EncryptJweJSONRequestBody, reqEditors ...RequestEditorFn) (*EncryptJweResponse, error)

	// SignJwsWithBodyWithResponse request with any body
	SignJwsWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*SignJwsResponse, error)

	SignJwsWithResponse(ctx context.Context, body SignJwsJSONRequestBody, reqEditors ...RequestEditorFn) (*SignJwsResponse, error)

	// SignJwtWithBodyWithResponse request with any body
	SignJwtWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*SignJwtResponse, error)

	SignJwtWithResponse(ctx context.Context, body SignJwtJSONRequestBody, reqEditors ...RequestEditorFn) (*SignJwtResponse, error)
}

type DecryptJweResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *struct {
		// Body The decrypted body as Base64 encoded string.
		Body []byte `json:"body"`

		// Headers The message headers.
		Headers map[string]interface{} `json:"headers"`
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
func (r DecryptJweResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r DecryptJweResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type EncryptJweResponse struct {
	Body                          []byte
	HTTPResponse                  *http.Response
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
func (r EncryptJweResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r EncryptJweResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type SignJwsResponse struct {
	Body                          []byte
	HTTPResponse                  *http.Response
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
func (r SignJwsResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r SignJwsResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type SignJwtResponse struct {
	Body                          []byte
	HTTPResponse                  *http.Response
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
func (r SignJwtResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r SignJwtResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// DecryptJweWithBodyWithResponse request with arbitrary body returning *DecryptJweResponse
func (c *ClientWithResponses) DecryptJweWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*DecryptJweResponse, error) {
	rsp, err := c.DecryptJweWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseDecryptJweResponse(rsp)
}

func (c *ClientWithResponses) DecryptJweWithResponse(ctx context.Context, body DecryptJweJSONRequestBody, reqEditors ...RequestEditorFn) (*DecryptJweResponse, error) {
	rsp, err := c.DecryptJwe(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseDecryptJweResponse(rsp)
}

// EncryptJweWithBodyWithResponse request with arbitrary body returning *EncryptJweResponse
func (c *ClientWithResponses) EncryptJweWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*EncryptJweResponse, error) {
	rsp, err := c.EncryptJweWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseEncryptJweResponse(rsp)
}

func (c *ClientWithResponses) EncryptJweWithResponse(ctx context.Context, body EncryptJweJSONRequestBody, reqEditors ...RequestEditorFn) (*EncryptJweResponse, error) {
	rsp, err := c.EncryptJwe(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseEncryptJweResponse(rsp)
}

// SignJwsWithBodyWithResponse request with arbitrary body returning *SignJwsResponse
func (c *ClientWithResponses) SignJwsWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*SignJwsResponse, error) {
	rsp, err := c.SignJwsWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseSignJwsResponse(rsp)
}

func (c *ClientWithResponses) SignJwsWithResponse(ctx context.Context, body SignJwsJSONRequestBody, reqEditors ...RequestEditorFn) (*SignJwsResponse, error) {
	rsp, err := c.SignJws(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseSignJwsResponse(rsp)
}

// SignJwtWithBodyWithResponse request with arbitrary body returning *SignJwtResponse
func (c *ClientWithResponses) SignJwtWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*SignJwtResponse, error) {
	rsp, err := c.SignJwtWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseSignJwtResponse(rsp)
}

func (c *ClientWithResponses) SignJwtWithResponse(ctx context.Context, body SignJwtJSONRequestBody, reqEditors ...RequestEditorFn) (*SignJwtResponse, error) {
	rsp, err := c.SignJwt(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseSignJwtResponse(rsp)
}

// ParseDecryptJweResponse parses an HTTP response from a DecryptJweWithResponse call
func ParseDecryptJweResponse(rsp *http.Response) (*DecryptJweResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &DecryptJweResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest struct {
			// Body The decrypted body as Base64 encoded string.
			Body []byte `json:"body"`

			// Headers The message headers.
			Headers map[string]interface{} `json:"headers"`
		}
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

// ParseEncryptJweResponse parses an HTTP response from a EncryptJweWithResponse call
func ParseEncryptJweResponse(rsp *http.Response) (*EncryptJweResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &EncryptJweResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
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

// ParseSignJwsResponse parses an HTTP response from a SignJwsWithResponse call
func ParseSignJwsResponse(rsp *http.Response) (*SignJwsResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &SignJwsResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
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

// ParseSignJwtResponse parses an HTTP response from a SignJwtWithResponse call
func ParseSignJwtResponse(rsp *http.Response) (*SignJwtResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &SignJwtResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
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
	// Decrypt a payload with the private key related to the KeyID in the header
	// (POST /internal/crypto/v1/decrypt_jwe)
	DecryptJwe(ctx echo.Context) error
	// Encrypt a payload and headers with the public key of the given DID into a JWE object
	// (POST /internal/crypto/v1/encrypt_jwe)
	EncryptJwe(ctx echo.Context) error
	// sign a payload and headers with the private key of the given kid into a JWS object
	// (POST /internal/crypto/v1/sign_jws)
	SignJws(ctx echo.Context) error
	// sign a JWT payload with the private key of the given kid
	// (POST /internal/crypto/v1/sign_jwt)
	SignJwt(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// DecryptJwe converts echo context to params.
func (w *ServerInterfaceWrapper) DecryptJwe(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.DecryptJwe(ctx)
	return err
}

// EncryptJwe converts echo context to params.
func (w *ServerInterfaceWrapper) EncryptJwe(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.EncryptJwe(ctx)
	return err
}

// SignJws converts echo context to params.
func (w *ServerInterfaceWrapper) SignJws(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.SignJws(ctx)
	return err
}

// SignJwt converts echo context to params.
func (w *ServerInterfaceWrapper) SignJwt(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.SignJwt(ctx)
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

	router.POST(baseURL+"/internal/crypto/v1/decrypt_jwe", wrapper.DecryptJwe)
	router.POST(baseURL+"/internal/crypto/v1/encrypt_jwe", wrapper.EncryptJwe)
	router.POST(baseURL+"/internal/crypto/v1/sign_jws", wrapper.SignJws)
	router.POST(baseURL+"/internal/crypto/v1/sign_jwt", wrapper.SignJwt)

}

type DecryptJweRequestObject struct {
	Body *DecryptJweJSONRequestBody
}

type DecryptJweResponseObject interface {
	VisitDecryptJweResponse(w http.ResponseWriter) error
}

type DecryptJwe200JSONResponse struct {
	// Body The decrypted body as Base64 encoded string.
	Body []byte `json:"body"`

	// Headers The message headers.
	Headers map[string]interface{} `json:"headers"`
}

func (response DecryptJwe200JSONResponse) VisitDecryptJweResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type DecryptJwedefaultApplicationProblemPlusJSONResponse struct {
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

func (response DecryptJwedefaultApplicationProblemPlusJSONResponse) VisitDecryptJweResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type EncryptJweRequestObject struct {
	Body *EncryptJweJSONRequestBody
}

type EncryptJweResponseObject interface {
	VisitEncryptJweResponse(w http.ResponseWriter) error
}

type EncryptJwe200TextResponse string

func (response EncryptJwe200TextResponse) VisitEncryptJweResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	_, err := w.Write([]byte(response))
	return err
}

type EncryptJwedefaultApplicationProblemPlusJSONResponse struct {
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

func (response EncryptJwedefaultApplicationProblemPlusJSONResponse) VisitEncryptJweResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type SignJwsRequestObject struct {
	Body *SignJwsJSONRequestBody
}

type SignJwsResponseObject interface {
	VisitSignJwsResponse(w http.ResponseWriter) error
}

type SignJws200TextResponse string

func (response SignJws200TextResponse) VisitSignJwsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	_, err := w.Write([]byte(response))
	return err
}

type SignJwsdefaultApplicationProblemPlusJSONResponse struct {
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

func (response SignJwsdefaultApplicationProblemPlusJSONResponse) VisitSignJwsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type SignJwtRequestObject struct {
	Body *SignJwtJSONRequestBody
}

type SignJwtResponseObject interface {
	VisitSignJwtResponse(w http.ResponseWriter) error
}

type SignJwt200TextResponse string

func (response SignJwt200TextResponse) VisitSignJwtResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	_, err := w.Write([]byte(response))
	return err
}

type SignJwtdefaultApplicationProblemPlusJSONResponse struct {
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

func (response SignJwtdefaultApplicationProblemPlusJSONResponse) VisitSignJwtResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {
	// Decrypt a payload with the private key related to the KeyID in the header
	// (POST /internal/crypto/v1/decrypt_jwe)
	DecryptJwe(ctx context.Context, request DecryptJweRequestObject) (DecryptJweResponseObject, error)
	// Encrypt a payload and headers with the public key of the given DID into a JWE object
	// (POST /internal/crypto/v1/encrypt_jwe)
	EncryptJwe(ctx context.Context, request EncryptJweRequestObject) (EncryptJweResponseObject, error)
	// sign a payload and headers with the private key of the given kid into a JWS object
	// (POST /internal/crypto/v1/sign_jws)
	SignJws(ctx context.Context, request SignJwsRequestObject) (SignJwsResponseObject, error)
	// sign a JWT payload with the private key of the given kid
	// (POST /internal/crypto/v1/sign_jwt)
	SignJwt(ctx context.Context, request SignJwtRequestObject) (SignJwtResponseObject, error)
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

// DecryptJwe operation middleware
func (sh *strictHandler) DecryptJwe(ctx echo.Context) error {
	var request DecryptJweRequestObject

	var body DecryptJweJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}
	request.Body = &body

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.DecryptJwe(ctx.Request().Context(), request.(DecryptJweRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "DecryptJwe")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(DecryptJweResponseObject); ok {
		return validResponse.VisitDecryptJweResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// EncryptJwe operation middleware
func (sh *strictHandler) EncryptJwe(ctx echo.Context) error {
	var request EncryptJweRequestObject

	var body EncryptJweJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}
	request.Body = &body

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.EncryptJwe(ctx.Request().Context(), request.(EncryptJweRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "EncryptJwe")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(EncryptJweResponseObject); ok {
		return validResponse.VisitEncryptJweResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// SignJws operation middleware
func (sh *strictHandler) SignJws(ctx echo.Context) error {
	var request SignJwsRequestObject

	var body SignJwsJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}
	request.Body = &body

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.SignJws(ctx.Request().Context(), request.(SignJwsRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "SignJws")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(SignJwsResponseObject); ok {
		return validResponse.VisitSignJwsResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// SignJwt operation middleware
func (sh *strictHandler) SignJwt(ctx echo.Context) error {
	var request SignJwtRequestObject

	var body SignJwtJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}
	request.Body = &body

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.SignJwt(ctx.Request().Context(), request.(SignJwtRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "SignJwt")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(SignJwtResponseObject); ok {
		return validResponse.VisitSignJwtResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}
