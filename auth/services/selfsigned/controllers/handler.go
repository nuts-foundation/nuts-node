package controllers

import (
	"bytes"
	"context"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/core"
	"html/template"
	"os"
	"strings"
)

type Handler struct {
	store types.SessionStore
}

func NewHandler(store types.SessionStore) *Handler {
	return &Handler{store}
}

// Routes registers the Echo routes for the API.
func (h Handler) Routes(router core.EchoRouter) {
	RegisterHandlers(router, NewStrictHandler(&h, nil))
}

func (h Handler) RenderEmployeeIDPage(ctx context.Context, request RenderEmployeeIDPageRequestObject) (RenderEmployeeIDPageResponseObject, error) {
	session, ok := h.store.Load(request.SessionID)
	if !ok {
		return RenderEmployeeIDPage404TexthtmlResponse{Body: strings.NewReader("session not found")}, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	tmpl, err := template.ParseFiles(wd + "/auth/services/selfsigned/templates/employee_identity_en.html")
	if err != nil {
		return nil, err
	}

	responseHTML := new(bytes.Buffer)
	if err := tmpl.Execute(responseHTML, session); err != nil {
		return nil, err
	}

	return RenderEmployeeIDPage200TexthtmlResponse{Body: responseHTML, ContentLength: int64(responseHTML.Len())}, nil
}

func (h Handler) HandleEmployeeIDForm(ctx context.Context, request HandleEmployeeIDFormRequestObject) (HandleEmployeeIDFormResponseObject, error) {
	//TODO implement me
	panic("implement me")
}
