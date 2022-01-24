// Package v2 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.8.2 DO NOT EDIT.
package v2

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

// Defines values for IssueVCRequestVisibility.
const (
	IssueVCRequestVisibilityPrivate IssueVCRequestVisibility = "private"

	IssueVCRequestVisibilityPublic IssueVCRequestVisibility = "public"
)

// DID according to Nuts specification
type DID string

// A request for issuing a new Verifiable Credential.
type IssueVCRequest struct {
	// The resolvable context of the credentialSubject as URI. If omitted, the "https://nuts.nl/credentials/v1" context is used.
	// Note: it is not needed to provide the "https://www.w3.org/2018/credentials/v1" context here.
	Context *string `json:"@context,omitempty"`

	// Subject of a Verifiable Credential identifying the holder and expressing claims.
	CredentialSubject CredentialSubject `json:"credentialSubject"`

	// rfc3339 time string until when the credential is valid.
	ExpirationDate *string `json:"expirationDate,omitempty"`

	// DID according to Nuts specification.
	Issuer string `json:"issuer"`

	// If set, the node publishes this credential to the network. This is the default behaviour.
	// When set to false, the caller is responsible for distributing the VC to a holder. When the issuer is
	// also the holder, it then can be used to directly create a presentation (self issued).
	PublishToNetwork *bool `json:"publishToNetwork,omitempty"`

	// Type definition for the credential.
	Type string `json:"type"`

	// When publishToNetwork is true, the credential can be published publicly of privately to the holder.
	// This field is mandatory if publishToNetwork is true to prevent accidents.
	Visibility *IssueVCRequestVisibility `json:"visibility,omitempty"`
}

// When publishToNetwork is true, the credential can be published publicly of privately to the holder.
// This field is mandatory if publishToNetwork is true to prevent accidents.
type IssueVCRequestVisibility string

// result of a Resolve operation.
type ResolutionResult struct {
	// If the credential is revoked, the field contains the revocation date.
	RevocationDate *string `json:"revocationDate,omitempty"`

	// A credential according to the W3C and Nuts specs.
	VerifiableCredential VerifiableCredential `json:"verifiableCredential"`
}

// Contains the verifiable credential verification result.
type VCVerificationResult struct {
	// Indicates what went wrong
	Message *string `json:"message,omitempty"`

	// Indicates the validity of the signature, issuer and revokation state.
	Validity bool `json:"validity"`
}

// IssueVCJSONBody defines parameters for IssueVC.
type IssueVCJSONBody IssueVCRequest

// ResolveIssuedVCParams defines parameters for ResolveIssuedVC.
type ResolveIssuedVCParams struct {
	// The type of the credential
	CredentialType string `json:"credentialType"`

	// the did of the issuer
	Issuer string `json:"issuer"`

	// the uri which indicates the subject (usually a did)
	Subject *string `json:"subject,omitempty"`
}

// VerifyVCJSONBody defines parameters for VerifyVC.
type VerifyVCJSONBody VerifiableCredential

// IssueVCJSONRequestBody defines body for IssueVC for application/json ContentType.
type IssueVCJSONRequestBody IssueVCJSONBody

// VerifyVCJSONRequestBody defines body for VerifyVC for application/json ContentType.
type VerifyVCJSONRequestBody VerifyVCJSONBody

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
	// IssueVC request with any body
	IssueVCWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	IssueVC(ctx context.Context, body IssueVCJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// ResolveIssuedVC request
	ResolveIssuedVC(ctx context.Context, params *ResolveIssuedVCParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// RevokeVC request
	RevokeVC(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// VerifyVC request with any body
	VerifyVCWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	VerifyVC(ctx context.Context, body VerifyVCJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) IssueVCWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewIssueVCRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) IssueVC(ctx context.Context, body IssueVCJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewIssueVCRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ResolveIssuedVC(ctx context.Context, params *ResolveIssuedVCParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewResolveIssuedVCRequest(c.Server, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) RevokeVC(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewRevokeVCRequest(c.Server, id)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) VerifyVCWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewVerifyVCRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) VerifyVC(ctx context.Context, body VerifyVCJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewVerifyVCRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewIssueVCRequest calls the generic IssueVC builder with application/json body
func NewIssueVCRequest(server string, body IssueVCJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewIssueVCRequestWithBody(server, "application/json", bodyReader)
}

// NewIssueVCRequestWithBody generates requests for IssueVC with any type of body
func NewIssueVCRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/vcr/v2/issuer/vc")
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

// NewResolveIssuedVCRequest generates requests for ResolveIssuedVC
func NewResolveIssuedVCRequest(server string, params *ResolveIssuedVCParams) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/vcr/v2/issuer/vc/search")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	queryValues := queryURL.Query()

	if queryFrag, err := runtime.StyleParamWithLocation("form", true, "credentialType", runtime.ParamLocationQuery, params.CredentialType); err != nil {
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

	if queryFrag, err := runtime.StyleParamWithLocation("form", true, "issuer", runtime.ParamLocationQuery, params.Issuer); err != nil {
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

	if params.Subject != nil {

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "subject", runtime.ParamLocationQuery, *params.Subject); err != nil {
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

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewRevokeVCRequest generates requests for RevokeVC
func NewRevokeVCRequest(server string, id string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "id", runtime.ParamLocationPath, id)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/vcr/v2/issuer/vc/%s", pathParam0)
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

// NewVerifyVCRequest calls the generic VerifyVC builder with application/json body
func NewVerifyVCRequest(server string, body VerifyVCJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewVerifyVCRequestWithBody(server, "application/json", bodyReader)
}

// NewVerifyVCRequestWithBody generates requests for VerifyVC with any type of body
func NewVerifyVCRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/vcr/v2/verifier/vc")
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
	// IssueVC request with any body
	IssueVCWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*IssueVCResponse, error)

	IssueVCWithResponse(ctx context.Context, body IssueVCJSONRequestBody, reqEditors ...RequestEditorFn) (*IssueVCResponse, error)

	// ResolveIssuedVC request
	ResolveIssuedVCWithResponse(ctx context.Context, params *ResolveIssuedVCParams, reqEditors ...RequestEditorFn) (*ResolveIssuedVCResponse, error)

	// RevokeVC request
	RevokeVCWithResponse(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*RevokeVCResponse, error)

	// VerifyVC request with any body
	VerifyVCWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*VerifyVCResponse, error)

	VerifyVCWithResponse(ctx context.Context, body VerifyVCJSONRequestBody, reqEditors ...RequestEditorFn) (*VerifyVCResponse, error)
}

type IssueVCResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r IssueVCResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r IssueVCResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ResolveIssuedVCResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r ResolveIssuedVCResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ResolveIssuedVCResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type RevokeVCResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r RevokeVCResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r RevokeVCResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type VerifyVCResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r VerifyVCResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r VerifyVCResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// IssueVCWithBodyWithResponse request with arbitrary body returning *IssueVCResponse
func (c *ClientWithResponses) IssueVCWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*IssueVCResponse, error) {
	rsp, err := c.IssueVCWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseIssueVCResponse(rsp)
}

func (c *ClientWithResponses) IssueVCWithResponse(ctx context.Context, body IssueVCJSONRequestBody, reqEditors ...RequestEditorFn) (*IssueVCResponse, error) {
	rsp, err := c.IssueVC(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseIssueVCResponse(rsp)
}

// ResolveIssuedVCWithResponse request returning *ResolveIssuedVCResponse
func (c *ClientWithResponses) ResolveIssuedVCWithResponse(ctx context.Context, params *ResolveIssuedVCParams, reqEditors ...RequestEditorFn) (*ResolveIssuedVCResponse, error) {
	rsp, err := c.ResolveIssuedVC(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseResolveIssuedVCResponse(rsp)
}

// RevokeVCWithResponse request returning *RevokeVCResponse
func (c *ClientWithResponses) RevokeVCWithResponse(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*RevokeVCResponse, error) {
	rsp, err := c.RevokeVC(ctx, id, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseRevokeVCResponse(rsp)
}

// VerifyVCWithBodyWithResponse request with arbitrary body returning *VerifyVCResponse
func (c *ClientWithResponses) VerifyVCWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*VerifyVCResponse, error) {
	rsp, err := c.VerifyVCWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseVerifyVCResponse(rsp)
}

func (c *ClientWithResponses) VerifyVCWithResponse(ctx context.Context, body VerifyVCJSONRequestBody, reqEditors ...RequestEditorFn) (*VerifyVCResponse, error) {
	rsp, err := c.VerifyVC(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseVerifyVCResponse(rsp)
}

// ParseIssueVCResponse parses an HTTP response from a IssueVCWithResponse call
func ParseIssueVCResponse(rsp *http.Response) (*IssueVCResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &IssueVCResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseResolveIssuedVCResponse parses an HTTP response from a ResolveIssuedVCWithResponse call
func ParseResolveIssuedVCResponse(rsp *http.Response) (*ResolveIssuedVCResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &ResolveIssuedVCResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseRevokeVCResponse parses an HTTP response from a RevokeVCWithResponse call
func ParseRevokeVCResponse(rsp *http.Response) (*RevokeVCResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &RevokeVCResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseVerifyVCResponse parses an HTTP response from a VerifyVCWithResponse call
func ParseVerifyVCResponse(rsp *http.Response) (*VerifyVCResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &VerifyVCResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Issues a new Verifiable Credential
	// (POST /internal/vcr/v2/issuer/vc)
	IssueVC(ctx echo.Context) error
	// Resolves verifiable credentials issued by this node which matches the search params
	// (GET /internal/vcr/v2/issuer/vc/search)
	ResolveIssuedVC(ctx echo.Context, params ResolveIssuedVCParams) error
	// Revoke an issued credential
	// (DELETE /internal/vcr/v2/issuer/vc/{id})
	RevokeVC(ctx echo.Context, id string) error
	// Verifies a Verifiable Credential
	// (POST /internal/vcr/v2/verifier/vc)
	VerifyVC(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// IssueVC converts echo context to params.
func (w *ServerInterfaceWrapper) IssueVC(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.IssueVC(ctx)
	return err
}

// ResolveIssuedVC converts echo context to params.
func (w *ServerInterfaceWrapper) ResolveIssuedVC(ctx echo.Context) error {
	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params ResolveIssuedVCParams
	// ------------- Required query parameter "credentialType" -------------

	err = runtime.BindQueryParameter("form", true, true, "credentialType", ctx.QueryParams(), &params.CredentialType)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter credentialType: %s", err))
	}

	// ------------- Required query parameter "issuer" -------------

	err = runtime.BindQueryParameter("form", true, true, "issuer", ctx.QueryParams(), &params.Issuer)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter issuer: %s", err))
	}

	// ------------- Optional query parameter "subject" -------------

	err = runtime.BindQueryParameter("form", true, false, "subject", ctx.QueryParams(), &params.Subject)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter subject: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.ResolveIssuedVC(ctx, params)
	return err
}

// RevokeVC converts echo context to params.
func (w *ServerInterfaceWrapper) RevokeVC(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithLocation("simple", false, "id", runtime.ParamLocationPath, ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.RevokeVC(ctx, id)
	return err
}

// VerifyVC converts echo context to params.
func (w *ServerInterfaceWrapper) VerifyVC(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.VerifyVC(ctx)
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
	router.Add(http.MethodPost, baseURL+"/internal/vcr/v2/issuer/vc", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("IssueVC", context)
		return wrapper.IssueVC(context)
	})
	router.Add(http.MethodGet, baseURL+"/internal/vcr/v2/issuer/vc/search", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("ResolveIssuedVC", context)
		return wrapper.ResolveIssuedVC(context)
	})
	router.Add(http.MethodDelete, baseURL+"/internal/vcr/v2/issuer/vc/:id", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("RevokeVC", context)
		return wrapper.RevokeVC(context)
	})
	router.Add(http.MethodPost, baseURL+"/internal/vcr/v2/verifier/vc", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("VerifyVC", context)
		return wrapper.VerifyVC(context)
	})

}
