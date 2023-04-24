package web

import (
	"bytes"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/core"
	"html/template"
	"net/http"
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
	RegisterHandlers(router, h)
}

func (h Handler) RenderEmployeeIDPage(ctx echo.Context, sessionID string, params RenderEmployeeIDPageParams) error {
	session, ok := h.store.Load(sessionID)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	// find the correct template language from the used contract template
	userContract, err := contract.ParseContractString(session.Contract, contract.StandardContractTemplates)
	if err != nil {
		return err
	}
	lang := userContract.Template.Language

	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	tmpl, err := template.ParseFiles(fmt.Sprintf("%s/auth/services/selfsigned/web/templates/employee_identity_%s.html", wd, strings.ToLower(string(lang))))
	if err != nil {
		return err
	}

	responseHTML := new(bytes.Buffer)
	if err := tmpl.Execute(responseHTML, session); err != nil {
		return err
	}

	// Check the current status before returning, this results that the form is only shown once
	if !h.store.CheckAndSetStatus(sessionID, types.SessionCreated, types.SessionInProgress) {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	return ctx.HTMLBlob(http.StatusOK, responseHTML.Bytes())
}

func (h Handler) HandleEmployeeIDForm(ctx echo.Context, sessionID string, params HandleEmployeeIDFormParams) error {
	session, ok := h.store.Load(sessionID)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	submitValue := ctx.FormValue("accept")

	if submitValue == "true" {
		session.Status = types.SessionCompleted
	} else if submitValue == "false" {
		session.Status = types.SessionCancelled
	}
	// Require the session to be in-progress to prevent double submission
	if !h.store.CheckAndSetStatus(sessionID, types.SessionInProgress, session.Status) {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	return ctx.Redirect(http.StatusFound, fmt.Sprintf("/public/auth/v1/means/employeeid/%s/done", sessionID))
}

func (h Handler) RenderEmployeeIDDonePage(ctx echo.Context, sessionID string) error {
	session, ok := h.store.Load(sessionID)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}
	// find the correct template language from the used contract template
	userContract, err := contract.ParseContractString(session.Contract, contract.StandardContractTemplates)
	if err != nil {
		return err
	}
	lang := userContract.Template.Language
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	tmpl, err := template.ParseFiles(fmt.Sprintf("%s/auth/services/selfsigned/web/templates/done_%s.html", wd, strings.ToLower(string(lang))))
	if err != nil {
		return err
	}
	responseHTML := new(bytes.Buffer)
	if err := tmpl.Execute(responseHTML, session); err != nil {
		return err
	}

	return ctx.HTMLBlob(http.StatusOK, responseHTML.Bytes())
}
