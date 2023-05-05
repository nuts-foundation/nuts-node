/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package web

import (
	"bytes"
	"embed"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/core"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
)

//go:embed templates/*
var webTemplates embed.FS

// donePagePathTemplate is the path to the done page, %s is the session ID
const donePagePathTemplate = `./%s/done`

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

	responseHTML := new(bytes.Buffer)
	err = renderTemplate("employee_identity", lang, session, responseHTML)
	if err != nil {
		return err
	}

	// Check the current status before returning, this results that the form is only shown once
	if !h.store.CheckAndSetStatus(sessionID, types.SessionCreated, types.SessionInProgress) {
		return echo.NewHTTPError(http.StatusNotFound, "no session with status created found")
	}

	return ctx.HTMLBlob(http.StatusOK, responseHTML.Bytes())
}

func (h Handler) HandleEmployeeIDForm(ctx echo.Context, sessionID string, params HandleEmployeeIDFormParams) error {
	session, ok := h.store.Load(sessionID)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	// check if the session has expired
	if time.Now().After(session.ExpiresAt) {
		h.store.CheckAndSetStatus(sessionID, types.SessionInProgress, types.SessionExpired)
		log.Logger().Warn("could not sign contract, session has expired")
		return echo.NewHTTPError(http.StatusNotFound, "session expired")
	}

	// load the form fields
	submitValue := ctx.FormValue("accept")
	secret := ctx.FormValue("secret")

	//  check the hidden secret field
	if session.Secret != secret {
		session.Status = types.SessionErrored
		log.Logger().Warn("could not sign contract, secret does not match")
	} else {
		if submitValue == "true" {
			session.Status = types.SessionCompleted
		} else if submitValue == "false" {
			session.Status = types.SessionCancelled
		}
	}
	// Require the session to be in-progress to prevent double submission
	if !h.store.CheckAndSetStatus(sessionID, types.SessionInProgress, session.Status) {
		log.Logger().Warn("could not sign contract, session is does not have the in-progress status")
		return echo.NewHTTPError(http.StatusNotFound, "no session with status in-progress found")
	}

	return ctx.Redirect(http.StatusFound, fmt.Sprintf(donePagePathTemplate, sessionID))
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

	responseHTML := new(bytes.Buffer)
	err = renderTemplate("done", lang, session, responseHTML)
	if err != nil {
		return err
	}

	return ctx.HTMLBlob(http.StatusOK, responseHTML.Bytes())
}

func renderTemplate(name string, lang contract.Language, session types.Session, target io.Writer) error {
	tmpl, err := template.ParseFS(webTemplates, fmt.Sprintf("templates/%s_%s.html", name, strings.ToLower(string(lang))))
	if err != nil {
		return err
	}
	return tmpl.Execute(target, session)
}
