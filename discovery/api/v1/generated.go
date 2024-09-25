// Package v1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.0 DO NOT EDIT.
package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/oapi-codegen/runtime"
	strictecho "github.com/oapi-codegen/runtime/strictmiddleware/echo"
)

const (
	JwtBearerAuthScopes = "jwtBearerAuth.Scopes"
)

// SearchResult defines model for SearchResult.
type SearchResult struct {
	// CredentialSubjectId The ID of the Verifiable Credential subject (holder), typically a DID.
	CredentialSubjectId string `json:"credential_subject_id"`

	// Fields Input descriptor IDs and their mapped values that from the Verifiable Credential.
	Fields map[string]interface{} `json:"fields"`

	// Id The ID of the Verifiable Presentation.
	Id string `json:"id"`

	// RegistrationParameters Additional parameters used when activating the service.
	// The authServerURL parameter is always present.
	RegistrationParameters map[string]interface{} `json:"registrationParameters"`
	Vp                     VerifiablePresentation `json:"vp"`
}

// ServiceActivationRequest Request for service activation.
type ServiceActivationRequest struct {
	// RegistrationParameters Additional parameters to use when activating a service. The contents of the object will be placed in the credentialSubject field of a DiscoveryRegistrationCredential.
	//
	// This, for example, allows use cases to require and clients to register specific endpoints.
	//
	// The authServerURL parameter is added automatically.
	RegistrationParameters *map[string]interface{} `json:"registrationParameters,omitempty"`
}

// SearchPresentationsParams defines parameters for SearchPresentations.
type SearchPresentationsParams struct {
	Query *map[string]string `form:"query,omitempty" json:"query,omitempty"`
}

// ActivateServiceForSubjectJSONRequestBody defines body for ActivateServiceForSubject for application/json ContentType.
type ActivateServiceForSubjectJSONRequestBody = ServiceActivationRequest

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Retrieves the list of Discovery Services.
	// (GET /internal/discovery/v1)
	GetServices(ctx echo.Context) error
	// Searches for presentations registered on the Discovery Service.
	// (GET /internal/discovery/v1/{serviceID})
	SearchPresentations(ctx echo.Context, serviceID string, params SearchPresentationsParams) error
	// Client API to deactivate the given subject from the Discovery Service.
	// (DELETE /internal/discovery/v1/{serviceID}/{subjectID})
	DeactivateServiceForSubject(ctx echo.Context, serviceID string, subjectID string) error
	// Retrieves the activation status of a subject on a Discovery Service.
	// (GET /internal/discovery/v1/{serviceID}/{subjectID})
	GetServiceActivation(ctx echo.Context, serviceID string, subjectID string) error
	// Client API to activate a subject on the specified Discovery Service.
	// (POST /internal/discovery/v1/{serviceID}/{subjectID})
	ActivateServiceForSubject(ctx echo.Context, serviceID string, subjectID string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// GetServices converts echo context to params.
func (w *ServerInterfaceWrapper) GetServices(ctx echo.Context) error {
	var err error

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GetServices(ctx)
	return err
}

// SearchPresentations converts echo context to params.
func (w *ServerInterfaceWrapper) SearchPresentations(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "serviceID" -------------
	var serviceID string

	err = runtime.BindStyledParameterWithOptions("simple", "serviceID", ctx.Param("serviceID"), &serviceID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter serviceID: %s", err))
	}

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Parameter object where we will unmarshal all parameters from the context
	var params SearchPresentationsParams
	// ------------- Optional query parameter "query" -------------

	err = runtime.BindQueryParameter("form", true, false, "query", ctx.QueryParams(), &params.Query)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter query: %s", err))
	}

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.SearchPresentations(ctx, serviceID, params)
	return err
}

// DeactivateServiceForSubject converts echo context to params.
func (w *ServerInterfaceWrapper) DeactivateServiceForSubject(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "serviceID" -------------
	var serviceID string

	err = runtime.BindStyledParameterWithOptions("simple", "serviceID", ctx.Param("serviceID"), &serviceID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter serviceID: %s", err))
	}

	// ------------- Path parameter "subjectID" -------------
	var subjectID string

	subjectID = ctx.Param("subjectID")

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.DeactivateServiceForSubject(ctx, serviceID, subjectID)
	return err
}

// GetServiceActivation converts echo context to params.
func (w *ServerInterfaceWrapper) GetServiceActivation(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "serviceID" -------------
	var serviceID string

	err = runtime.BindStyledParameterWithOptions("simple", "serviceID", ctx.Param("serviceID"), &serviceID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter serviceID: %s", err))
	}

	// ------------- Path parameter "subjectID" -------------
	var subjectID string

	subjectID = ctx.Param("subjectID")

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.GetServiceActivation(ctx, serviceID, subjectID)
	return err
}

// ActivateServiceForSubject converts echo context to params.
func (w *ServerInterfaceWrapper) ActivateServiceForSubject(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "serviceID" -------------
	var serviceID string

	err = runtime.BindStyledParameterWithOptions("simple", "serviceID", ctx.Param("serviceID"), &serviceID, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter serviceID: %s", err))
	}

	// ------------- Path parameter "subjectID" -------------
	var subjectID string

	subjectID = ctx.Param("subjectID")

	ctx.Set(JwtBearerAuthScopes, []string{})

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.ActivateServiceForSubject(ctx, serviceID, subjectID)
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

	router.GET(baseURL+"/internal/discovery/v1", wrapper.GetServices)
	router.GET(baseURL+"/internal/discovery/v1/:serviceID", wrapper.SearchPresentations)
	router.DELETE(baseURL+"/internal/discovery/v1/:serviceID/:subjectID", wrapper.DeactivateServiceForSubject)
	router.GET(baseURL+"/internal/discovery/v1/:serviceID/:subjectID", wrapper.GetServiceActivation)
	router.POST(baseURL+"/internal/discovery/v1/:serviceID/:subjectID", wrapper.ActivateServiceForSubject)

}

type GetServicesRequestObject struct {
}

type GetServicesResponseObject interface {
	VisitGetServicesResponse(w http.ResponseWriter) error
}

type GetServices200JSONResponse []ServiceDefinition

func (response GetServices200JSONResponse) VisitGetServicesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetServicesdefaultApplicationProblemPlusJSONResponse struct {
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

func (response GetServicesdefaultApplicationProblemPlusJSONResponse) VisitGetServicesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type SearchPresentationsRequestObject struct {
	ServiceID string `json:"serviceID"`
	Params    SearchPresentationsParams
}

type SearchPresentationsResponseObject interface {
	VisitSearchPresentationsResponse(w http.ResponseWriter) error
}

type SearchPresentations200JSONResponse []SearchResult

func (response SearchPresentations200JSONResponse) VisitSearchPresentationsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type SearchPresentationsdefaultApplicationProblemPlusJSONResponse struct {
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

func (response SearchPresentationsdefaultApplicationProblemPlusJSONResponse) VisitSearchPresentationsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type DeactivateServiceForSubjectRequestObject struct {
	ServiceID string `json:"serviceID"`
	SubjectID string `json:"subjectID"`
}

type DeactivateServiceForSubjectResponseObject interface {
	VisitDeactivateServiceForSubjectResponse(w http.ResponseWriter) error
}

type DeactivateServiceForSubject200Response struct {
}

func (response DeactivateServiceForSubject200Response) VisitDeactivateServiceForSubjectResponse(w http.ResponseWriter) error {
	w.WriteHeader(200)
	return nil
}

type DeactivateServiceForSubject202JSONResponse struct {
	// Reason Description of why removal of the registration failed.
	Reason string `json:"reason"`
}

func (response DeactivateServiceForSubject202JSONResponse) VisitDeactivateServiceForSubjectResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)

	return json.NewEncoder(w).Encode(response)
}

type DeactivateServiceForSubject400ApplicationProblemPlusJSONResponse struct {
	// Detail A human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail"`

	// Status HTTP statuscode
	Status float32 `json:"status"`

	// Title A short, human-readable summary of the problem type.
	Title string `json:"title"`
}

func (response DeactivateServiceForSubject400ApplicationProblemPlusJSONResponse) VisitDeactivateServiceForSubjectResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type DeactivateServiceForSubjectdefaultApplicationProblemPlusJSONResponse struct {
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

func (response DeactivateServiceForSubjectdefaultApplicationProblemPlusJSONResponse) VisitDeactivateServiceForSubjectResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type GetServiceActivationRequestObject struct {
	ServiceID string `json:"serviceID"`
	SubjectID string `json:"subjectID"`
}

type GetServiceActivationResponseObject interface {
	VisitGetServiceActivationResponse(w http.ResponseWriter) error
}

type GetServiceActivation200JSONResponse struct {
	// Activated Whether the Discovery Service is activated for the given subject
	Activated bool `json:"activated"`

	// Error Error message if status is "error".
	Error *string `json:"error,omitempty"`

	// Status Status of the activation. "active" or "error".
	Status GetServiceActivation200JSONResponseStatus `json:"status"`

	// Vp List of VPs on the Discovery Service for the subject. One per DID method registered on the Service.
	// The list can be empty even if activated==true if none of the DIDs of a subject is actually registered on the Discovery Service.
	Vp *[]VerifiablePresentation `json:"vp,omitempty"`
}

func (response GetServiceActivation200JSONResponse) VisitGetServiceActivationResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetServiceActivationdefaultApplicationProblemPlusJSONResponse struct {
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

func (response GetServiceActivationdefaultApplicationProblemPlusJSONResponse) VisitGetServiceActivationResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

type ActivateServiceForSubjectRequestObject struct {
	ServiceID string `json:"serviceID"`
	SubjectID string `json:"subjectID"`
	Body      *ActivateServiceForSubjectJSONRequestBody
}

type ActivateServiceForSubjectResponseObject interface {
	VisitActivateServiceForSubjectResponse(w http.ResponseWriter) error
}

type ActivateServiceForSubject200Response struct {
}

func (response ActivateServiceForSubject200Response) VisitActivateServiceForSubjectResponse(w http.ResponseWriter) error {
	w.WriteHeader(200)
	return nil
}

type ActivateServiceForSubject400ApplicationProblemPlusJSONResponse struct {
	// Detail A human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail"`

	// Status HTTP statuscode
	Status float32 `json:"status"`

	// Title A short, human-readable summary of the problem type.
	Title string `json:"title"`
}

func (response ActivateServiceForSubject400ApplicationProblemPlusJSONResponse) VisitActivateServiceForSubjectResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type ActivateServiceForSubject412ApplicationProblemPlusJSONResponse struct {
	// Detail A human-readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail"`

	// Status HTTP statuscode
	Status float32 `json:"status"`

	// Title A short, human-readable summary of the problem type.
	Title string `json:"title"`
}

func (response ActivateServiceForSubject412ApplicationProblemPlusJSONResponse) VisitActivateServiceForSubjectResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(412)

	return json.NewEncoder(w).Encode(response)
}

type ActivateServiceForSubjectdefaultApplicationProblemPlusJSONResponse struct {
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

func (response ActivateServiceForSubjectdefaultApplicationProblemPlusJSONResponse) VisitActivateServiceForSubjectResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(response.StatusCode)

	return json.NewEncoder(w).Encode(response.Body)
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {
	// Retrieves the list of Discovery Services.
	// (GET /internal/discovery/v1)
	GetServices(ctx context.Context, request GetServicesRequestObject) (GetServicesResponseObject, error)
	// Searches for presentations registered on the Discovery Service.
	// (GET /internal/discovery/v1/{serviceID})
	SearchPresentations(ctx context.Context, request SearchPresentationsRequestObject) (SearchPresentationsResponseObject, error)
	// Client API to deactivate the given subject from the Discovery Service.
	// (DELETE /internal/discovery/v1/{serviceID}/{subjectID})
	DeactivateServiceForSubject(ctx context.Context, request DeactivateServiceForSubjectRequestObject) (DeactivateServiceForSubjectResponseObject, error)
	// Retrieves the activation status of a subject on a Discovery Service.
	// (GET /internal/discovery/v1/{serviceID}/{subjectID})
	GetServiceActivation(ctx context.Context, request GetServiceActivationRequestObject) (GetServiceActivationResponseObject, error)
	// Client API to activate a subject on the specified Discovery Service.
	// (POST /internal/discovery/v1/{serviceID}/{subjectID})
	ActivateServiceForSubject(ctx context.Context, request ActivateServiceForSubjectRequestObject) (ActivateServiceForSubjectResponseObject, error)
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

// GetServices operation middleware
func (sh *strictHandler) GetServices(ctx echo.Context) error {
	var request GetServicesRequestObject

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.GetServices(ctx.Request().Context(), request.(GetServicesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetServices")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(GetServicesResponseObject); ok {
		return validResponse.VisitGetServicesResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// SearchPresentations operation middleware
func (sh *strictHandler) SearchPresentations(ctx echo.Context, serviceID string, params SearchPresentationsParams) error {
	var request SearchPresentationsRequestObject

	request.ServiceID = serviceID
	request.Params = params

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.SearchPresentations(ctx.Request().Context(), request.(SearchPresentationsRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "SearchPresentations")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(SearchPresentationsResponseObject); ok {
		return validResponse.VisitSearchPresentationsResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// DeactivateServiceForSubject operation middleware
func (sh *strictHandler) DeactivateServiceForSubject(ctx echo.Context, serviceID string, subjectID string) error {
	var request DeactivateServiceForSubjectRequestObject

	request.ServiceID = serviceID
	request.SubjectID = subjectID

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.DeactivateServiceForSubject(ctx.Request().Context(), request.(DeactivateServiceForSubjectRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "DeactivateServiceForSubject")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(DeactivateServiceForSubjectResponseObject); ok {
		return validResponse.VisitDeactivateServiceForSubjectResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// GetServiceActivation operation middleware
func (sh *strictHandler) GetServiceActivation(ctx echo.Context, serviceID string, subjectID string) error {
	var request GetServiceActivationRequestObject

	request.ServiceID = serviceID
	request.SubjectID = subjectID

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.GetServiceActivation(ctx.Request().Context(), request.(GetServiceActivationRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetServiceActivation")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(GetServiceActivationResponseObject); ok {
		return validResponse.VisitGetServiceActivationResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}

// ActivateServiceForSubject operation middleware
func (sh *strictHandler) ActivateServiceForSubject(ctx echo.Context, serviceID string, subjectID string) error {
	var request ActivateServiceForSubjectRequestObject

	request.ServiceID = serviceID
	request.SubjectID = subjectID

	var body ActivateServiceForSubjectJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}
	request.Body = &body

	handler := func(ctx echo.Context, request interface{}) (interface{}, error) {
		return sh.ssi.ActivateServiceForSubject(ctx.Request().Context(), request.(ActivateServiceForSubjectRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "ActivateServiceForSubject")
	}

	response, err := handler(ctx, request)

	if err != nil {
		return err
	} else if validResponse, ok := response.(ActivateServiceForSubjectResponseObject); ok {
		return validResponse.VisitActivateServiceForSubjectResponse(ctx.Response())
	} else if response != nil {
		return fmt.Errorf("unexpected response type: %T", response)
	}
	return nil
}
