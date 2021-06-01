// Package v1 provides primitives to interact with the openapi HTTP API.
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

// CompoundService defines model for CompoundService.
type CompoundService struct {
	// Embedded fields due to inline allOf schema
	Id string `json:"id"`
	// Embedded struct due to allOf(#/components/schemas/CompoundServiceProperties)
	CompoundServiceProperties `yaml:",inline"`
}

// A creation request for a compound service that references endpoints.
type CompoundServiceProperties struct {

	// A map containing service references.
	ServiceEndpoint map[string]interface{} `json:"serviceEndpoint"`

	// type of the endpoint. May be freely choosen.
	Type string `json:"type"`
}

// A combination of type and URL.
type EndpointCreateRequest struct {

	// A URL.
	Endpoint string `json:"endpoint"`

	// type of the endpoint. May be freely choosen.
	Type string `json:"type"`
}

// AddCompoundServiceJSONBody defines parameters for AddCompoundService.
type AddCompoundServiceJSONBody CompoundServiceProperties

// UpdateContactInformationJSONBody defines parameters for UpdateContactInformation.
type UpdateContactInformationJSONBody ContactInformation

// AddEndpointJSONBody defines parameters for AddEndpoint.
type AddEndpointJSONBody EndpointCreateRequest

// AddCompoundServiceJSONRequestBody defines body for AddCompoundService for application/json ContentType.
type AddCompoundServiceJSONRequestBody AddCompoundServiceJSONBody

// UpdateContactInformationJSONRequestBody defines body for UpdateContactInformation for application/json ContentType.
type UpdateContactInformationJSONRequestBody UpdateContactInformationJSONBody

// AddEndpointJSONRequestBody defines body for AddEndpoint for application/json ContentType.
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
	// GetCompoundServices request
	GetCompoundServices(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// AddCompoundService request  with any body
	AddCompoundServiceWithBody(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	AddCompoundService(ctx context.Context, did string, body AddCompoundServiceJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetContactInformation request
	GetContactInformation(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// UpdateContactInformation request  with any body
	UpdateContactInformationWithBody(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	UpdateContactInformation(ctx context.Context, did string, body UpdateContactInformationJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// AddEndpoint request  with any body
	AddEndpointWithBody(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	AddEndpoint(ctx context.Context, did string, body AddEndpointJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// DeleteService request
	DeleteService(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) GetCompoundServices(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetCompoundServicesRequest(c.Server, did)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) AddCompoundServiceWithBody(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewAddCompoundServiceRequestWithBody(c.Server, did, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) AddCompoundService(ctx context.Context, did string, body AddCompoundServiceJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewAddCompoundServiceRequest(c.Server, did, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetContactInformation(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetContactInformationRequest(c.Server, did)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) UpdateContactInformationWithBody(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewUpdateContactInformationRequestWithBody(c.Server, did, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) UpdateContactInformation(ctx context.Context, did string, body UpdateContactInformationJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewUpdateContactInformationRequest(c.Server, did, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) AddEndpointWithBody(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewAddEndpointRequestWithBody(c.Server, did, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) AddEndpoint(ctx context.Context, did string, body AddEndpointJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewAddEndpointRequest(c.Server, did, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) DeleteService(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewDeleteServiceRequest(c.Server, id)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewGetCompoundServicesRequest generates requests for GetCompoundServices
func NewGetCompoundServicesRequest(server string, did string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "did", runtime.ParamLocationPath, did)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/didman/v1/did/%s/compoundservice", pathParam0)
	if operationPath[0] == '/' {
		operationPath = operationPath[1:]
	}
	operationURL := url.URL{
		Path: operationPath,
	}

	queryURL := serverURL.ResolveReference(&operationURL)

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewAddCompoundServiceRequest calls the generic AddCompoundService builder with application/json body
func NewAddCompoundServiceRequest(server string, did string, body AddCompoundServiceJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewAddCompoundServiceRequestWithBody(server, did, "application/json", bodyReader)
}

// NewAddCompoundServiceRequestWithBody generates requests for AddCompoundService with any type of body
func NewAddCompoundServiceRequestWithBody(server string, did string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "did", runtime.ParamLocationPath, did)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/didman/v1/did/%s/compoundservice", pathParam0)
	if operationPath[0] == '/' {
		operationPath = operationPath[1:]
	}
	operationURL := url.URL{
		Path: operationPath,
	}

	queryURL := serverURL.ResolveReference(&operationURL)

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewGetContactInformationRequest generates requests for GetContactInformation
func NewGetContactInformationRequest(server string, did string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "did", runtime.ParamLocationPath, did)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/didman/v1/did/%s/contactinfo", pathParam0)
	if operationPath[0] == '/' {
		operationPath = operationPath[1:]
	}
	operationURL := url.URL{
		Path: operationPath,
	}

	queryURL := serverURL.ResolveReference(&operationURL)

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewUpdateContactInformationRequest calls the generic UpdateContactInformation builder with application/json body
func NewUpdateContactInformationRequest(server string, did string, body UpdateContactInformationJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewUpdateContactInformationRequestWithBody(server, did, "application/json", bodyReader)
}

// NewUpdateContactInformationRequestWithBody generates requests for UpdateContactInformation with any type of body
func NewUpdateContactInformationRequestWithBody(server string, did string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "did", runtime.ParamLocationPath, did)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/didman/v1/did/%s/contactinfo", pathParam0)
	if operationPath[0] == '/' {
		operationPath = operationPath[1:]
	}
	operationURL := url.URL{
		Path: operationPath,
	}

	queryURL := serverURL.ResolveReference(&operationURL)

	req, err := http.NewRequest("PUT", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
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

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "did", runtime.ParamLocationPath, did)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/didman/v1/did/%s/endpoint", pathParam0)
	if operationPath[0] == '/' {
		operationPath = operationPath[1:]
	}
	operationURL := url.URL{
		Path: operationPath,
	}

	queryURL := serverURL.ResolveReference(&operationURL)

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewDeleteServiceRequest generates requests for DeleteService
func NewDeleteServiceRequest(server string, id string) (*http.Request, error) {
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

	operationPath := fmt.Sprintf("/internal/didman/v1/service/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = operationPath[1:]
	}
	operationURL := url.URL{
		Path: operationPath,
	}

	queryURL := serverURL.ResolveReference(&operationURL)

	req, err := http.NewRequest("DELETE", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

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
	// GetCompoundServices request
	GetCompoundServicesWithResponse(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*GetCompoundServicesResponse, error)

	// AddCompoundService request  with any body
	AddCompoundServiceWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*AddCompoundServiceResponse, error)

	AddCompoundServiceWithResponse(ctx context.Context, did string, body AddCompoundServiceJSONRequestBody, reqEditors ...RequestEditorFn) (*AddCompoundServiceResponse, error)

	// GetContactInformation request
	GetContactInformationWithResponse(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*GetContactInformationResponse, error)

	// UpdateContactInformation request  with any body
	UpdateContactInformationWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*UpdateContactInformationResponse, error)

	UpdateContactInformationWithResponse(ctx context.Context, did string, body UpdateContactInformationJSONRequestBody, reqEditors ...RequestEditorFn) (*UpdateContactInformationResponse, error)

	// AddEndpoint request  with any body
	AddEndpointWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*AddEndpointResponse, error)

	AddEndpointWithResponse(ctx context.Context, did string, body AddEndpointJSONRequestBody, reqEditors ...RequestEditorFn) (*AddEndpointResponse, error)

	// DeleteService request
	DeleteServiceWithResponse(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*DeleteServiceResponse, error)
}

type GetCompoundServicesResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]CompoundService
}

// Status returns HTTPResponse.Status
func (r GetCompoundServicesResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetCompoundServicesResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type AddCompoundServiceResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *CompoundService
}

// Status returns HTTPResponse.Status
func (r AddCompoundServiceResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r AddCompoundServiceResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetContactInformationResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *ContactInformation
}

// Status returns HTTPResponse.Status
func (r GetContactInformationResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetContactInformationResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type UpdateContactInformationResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *ContactInformation
}

// Status returns HTTPResponse.Status
func (r UpdateContactInformationResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r UpdateContactInformationResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
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

type DeleteServiceResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r DeleteServiceResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r DeleteServiceResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// GetCompoundServicesWithResponse request returning *GetCompoundServicesResponse
func (c *ClientWithResponses) GetCompoundServicesWithResponse(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*GetCompoundServicesResponse, error) {
	rsp, err := c.GetCompoundServices(ctx, did, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetCompoundServicesResponse(rsp)
}

// AddCompoundServiceWithBodyWithResponse request with arbitrary body returning *AddCompoundServiceResponse
func (c *ClientWithResponses) AddCompoundServiceWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*AddCompoundServiceResponse, error) {
	rsp, err := c.AddCompoundServiceWithBody(ctx, did, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseAddCompoundServiceResponse(rsp)
}

func (c *ClientWithResponses) AddCompoundServiceWithResponse(ctx context.Context, did string, body AddCompoundServiceJSONRequestBody, reqEditors ...RequestEditorFn) (*AddCompoundServiceResponse, error) {
	rsp, err := c.AddCompoundService(ctx, did, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseAddCompoundServiceResponse(rsp)
}

// GetContactInformationWithResponse request returning *GetContactInformationResponse
func (c *ClientWithResponses) GetContactInformationWithResponse(ctx context.Context, did string, reqEditors ...RequestEditorFn) (*GetContactInformationResponse, error) {
	rsp, err := c.GetContactInformation(ctx, did, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetContactInformationResponse(rsp)
}

// UpdateContactInformationWithBodyWithResponse request with arbitrary body returning *UpdateContactInformationResponse
func (c *ClientWithResponses) UpdateContactInformationWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*UpdateContactInformationResponse, error) {
	rsp, err := c.UpdateContactInformationWithBody(ctx, did, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseUpdateContactInformationResponse(rsp)
}

func (c *ClientWithResponses) UpdateContactInformationWithResponse(ctx context.Context, did string, body UpdateContactInformationJSONRequestBody, reqEditors ...RequestEditorFn) (*UpdateContactInformationResponse, error) {
	rsp, err := c.UpdateContactInformation(ctx, did, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseUpdateContactInformationResponse(rsp)
}

// AddEndpointWithBodyWithResponse request with arbitrary body returning *AddEndpointResponse
func (c *ClientWithResponses) AddEndpointWithBodyWithResponse(ctx context.Context, did string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*AddEndpointResponse, error) {
	rsp, err := c.AddEndpointWithBody(ctx, did, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseAddEndpointResponse(rsp)
}

func (c *ClientWithResponses) AddEndpointWithResponse(ctx context.Context, did string, body AddEndpointJSONRequestBody, reqEditors ...RequestEditorFn) (*AddEndpointResponse, error) {
	rsp, err := c.AddEndpoint(ctx, did, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseAddEndpointResponse(rsp)
}

// DeleteServiceWithResponse request returning *DeleteServiceResponse
func (c *ClientWithResponses) DeleteServiceWithResponse(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*DeleteServiceResponse, error) {
	rsp, err := c.DeleteService(ctx, id, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseDeleteServiceResponse(rsp)
}

// ParseGetCompoundServicesResponse parses an HTTP response from a GetCompoundServicesWithResponse call
func ParseGetCompoundServicesResponse(rsp *http.Response) (*GetCompoundServicesResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &GetCompoundServicesResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []CompoundService
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseAddCompoundServiceResponse parses an HTTP response from a AddCompoundServiceWithResponse call
func ParseAddCompoundServiceResponse(rsp *http.Response) (*AddCompoundServiceResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &AddCompoundServiceResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest CompoundService
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseGetContactInformationResponse parses an HTTP response from a GetContactInformationWithResponse call
func ParseGetContactInformationResponse(rsp *http.Response) (*GetContactInformationResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &GetContactInformationResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest ContactInformation
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseUpdateContactInformationResponse parses an HTTP response from a UpdateContactInformationWithResponse call
func ParseUpdateContactInformationResponse(rsp *http.Response) (*UpdateContactInformationResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &UpdateContactInformationResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest ContactInformation
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
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

// ParseDeleteServiceResponse parses an HTTP response from a DeleteServiceWithResponse call
func ParseDeleteServiceResponse(rsp *http.Response) (*DeleteServiceResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &DeleteServiceResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Get a list of compound services for a DID document.
	// (GET /internal/didman/v1/did/{did}/compoundservice)
	GetCompoundServices(ctx echo.Context, did string) error
	// Add a compound service to a DID Document.
	// (POST /internal/didman/v1/did/{did}/compoundservice)
	AddCompoundService(ctx echo.Context, did string) error

	// (GET /internal/didman/v1/did/{did}/contactinfo)
	GetContactInformation(ctx echo.Context, did string) error
	// Add a predetermined DID Service with real life contact information
	// (PUT /internal/didman/v1/did/{did}/contactinfo)
	UpdateContactInformation(ctx echo.Context, did string) error
	// Add an endpoint to a DID Document.
	// (POST /internal/didman/v1/did/{did}/endpoint)
	AddEndpoint(ctx echo.Context, did string) error
	// Remove a service from a DID Document.
	// (DELETE /internal/didman/v1/service/{id})
	DeleteService(ctx echo.Context, id string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// GetCompoundServices converts echo context to params.
func (w *ServerInterfaceWrapper) GetCompoundServices(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetCompoundServices(ctx, did)
	return err
}

// AddCompoundService converts echo context to params.
func (w *ServerInterfaceWrapper) AddCompoundService(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.AddCompoundService(ctx, did)
	return err
}

// GetContactInformation converts echo context to params.
func (w *ServerInterfaceWrapper) GetContactInformation(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetContactInformation(ctx, did)
	return err
}

// UpdateContactInformation converts echo context to params.
func (w *ServerInterfaceWrapper) UpdateContactInformation(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.UpdateContactInformation(ctx, did)
	return err
}

// AddEndpoint converts echo context to params.
func (w *ServerInterfaceWrapper) AddEndpoint(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "did" -------------
	var did string

	err = runtime.BindStyledParameterWithLocation("simple", false, "did", runtime.ParamLocationPath, ctx.Param("did"), &did)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter did: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.AddEndpoint(ctx, did)
	return err
}

// DeleteService converts echo context to params.
func (w *ServerInterfaceWrapper) DeleteService(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "id" -------------
	var id string

	err = runtime.BindStyledParameterWithLocation("simple", false, "id", runtime.ParamLocationPath, ctx.Param("id"), &id)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter id: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.DeleteService(ctx, id)
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
	router.Add(http.MethodGet, baseURL+"/internal/didman/v1/did/:did/compoundservice", func(context echo.Context) error {
		context.Set("!!OperationId", "GetCompoundServices")
		if resolver, ok := si.(ErrorStatusCodeResolver); ok {
			context.Set("!!StatusCodeResolver", resolver)
		}
		return wrapper.GetCompoundServices(context)
	})
	router.Add(http.MethodPost, baseURL+"/internal/didman/v1/did/:did/compoundservice", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("AddCompoundService", context)
		return wrapper.AddCompoundService(context)
	})
	router.Add(http.MethodGet, baseURL+"/internal/didman/v1/did/:did/contactinfo", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("GetContactInformation", context)
		return wrapper.GetContactInformation(context)
	})
	router.Add(http.MethodPut, baseURL+"/internal/didman/v1/did/:did/contactinfo", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("UpdateContactInformation", context)
		return wrapper.UpdateContactInformation(context)
	})
	router.Add(http.MethodPost, baseURL+"/internal/didman/v1/did/:did/endpoint", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("AddEndpoint", context)
		return wrapper.AddEndpoint(context)
	})
	router.Add(http.MethodDelete, baseURL+"/internal/didman/v1/service/:id", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("DeleteService", context)
		return wrapper.DeleteService(context)
	})

}
