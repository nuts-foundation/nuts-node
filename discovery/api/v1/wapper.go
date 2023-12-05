package v1

import (
	"context"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery"
	"net/http"
)

var _ StrictServerInterface = (*Wrapper)(nil)
var _ core.ErrorStatusCodeResolver = (*Wrapper)(nil)

// Wrapper implements the generated interface from oapi-codegen
type Wrapper struct {
	Server discovery.Server
}

// ResolveStatusCode maps errors returned by this API to specific HTTP status codes.
func (w *Wrapper) ResolveStatusCode(err error) int {
	// todo
	switch {
	case errors.Is(err, discovery.ErrServerModeDisabled):
		return http.StatusBadRequest
	case errors.Is(err, discovery.ErrInvalidPresentation):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// Routes registers the routes from the open api spec to the echo router.
func (w *Wrapper) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(w, []StrictMiddlewareFunc{
		func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
			return func(ctx echo.Context, request interface{}) (response interface{}, err error) {
				ctx.Set(core.OperationIDContextKey, operationID)
				ctx.Set(core.ModuleNameContextKey, discovery.ModuleName)
				ctx.Set(core.StatusCodeResolverContextKey, w)
				return f(ctx, request)
			}
		},
		//func(f StrictHandlerFunc, operationID string) StrictHandlerFunc {
		//	return audit.StrictMiddleware(f, discover.ModuleName, operationID)
		//},
	}))
}

func (w *Wrapper) GetPresentations(_ context.Context, request GetPresentationsRequestObject) (GetPresentationsResponseObject, error) {
	var tag *discovery.Tag
	if request.Params.Tag != nil {
		tag = new(discovery.Tag)
		*tag = discovery.Tag(*request.Params.Tag)
	}
	presentations, newTag, err := w.Server.Get(request.ServiceID, tag)
	if err != nil {
		return nil, err
	}
	return GetPresentations200JSONResponse{
		Entries: presentations,
		Tag:     string(*newTag),
	}, nil
}

func (w *Wrapper) RegisterPresentation(_ context.Context, request RegisterPresentationRequestObject) (RegisterPresentationResponseObject, error) {
	err := w.Server.Add(request.ServiceID, *request.Body)
	if err != nil {
		return nil, err
	}
	return RegisterPresentation201Response{}, nil
}

func (w *Wrapper) SearchPresentations(_ context.Context, request SearchPresentationsRequestObject) (SearchPresentationsResponseObject, error) {
	// TODO: Do we need this from the start on, or are we hooking up VCR.SearchVCs to Discovery.Search()?
	panic("implement me")
}
