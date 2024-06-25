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
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/core"
)

//go:embed templates/*
var webTemplates embed.FS

// donePagePathTemplate is the path to the done page, %s is the session ID
const donePagePathTemplate = `./%s`

// PageParams is the data that is passed to the template
type PageData struct {
	Session types.Session
}

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

func (h Handler) RenderEmployeeIDPage(ctx echo.Context, sessionID SessionID) error {
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

	pageData := PageData{
		Session: session,
	}

	var templateToRender string
	if h.store.CheckAndSetStatus(sessionID, types.SessionCreated, types.SessionInProgress) {
		templateToRender = "employee_identity"
	} else {
		templateToRender = "done"
	}
	responseHTML := new(bytes.Buffer)
	if err := renderTemplate(templateToRender, lang, pageData, responseHTML); err != nil {
		return err
	}
	return ctx.HTMLBlob(http.StatusOK, responseHTML.Bytes())
}

func (h Handler) HandleEmployeeIDForm(ctx echo.Context, sessionID SessionID) error {
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

	var newStatus string

	// Update the signing status based on the form submission:
	if session.Secret != secret {
		//  If secret is not correct, set status to errored
		newStatus = types.SessionErrored
		log.Logger().Warn("could not sign contract, secret does not match")
	} else {
		// check if the form was submitted or cancelled
		if submitValue == "true" {
			newStatus = types.SessionCompleted
		} else if submitValue == "false" {
			newStatus = types.SessionCancelled
		}
	}
	// Require the session to be in-progress to prevent double submission
	if !h.store.CheckAndSetStatus(sessionID, types.SessionInProgress, newStatus) {
		log.Logger().Warn("could not sign contract, session is does not have the in-progress status")
		return echo.NewHTTPError(http.StatusNotFound, "no session with status in-progress found")
	}

	return ctx.Redirect(http.StatusFound, fmt.Sprintf(donePagePathTemplate, sessionID))
}

// func (h Handler) RenderEmployeeIDDonePage(ctx echo.Context, sessionID SessionID, params RenderEmployeeIDDonePageParams) error {
// 	session, ok := h.store.Load(sessionID)
// 	if !ok {
// 		return echo.NewHTTPError(http.StatusNotFound, "session not found")
// 	}
// 	// find the correct template language from the used contract template
// 	userContract, err := contract.ParseContractString(session.Contract, contract.StandardContractTemplates)
// 	if err != nil {
// 		return err
// 	}
// 	lang := userContract.Template.Language
//
// 	responseHTML := new(bytes.Buffer)
// 	pageData := PageData{
// 		DisableDarkMode: params.DisableDarkMode,
// 		Session:         session,
// 	}
// 	err = renderTemplate("done", lang, pageData, responseHTML)
// 	if err != nil {
// 		return err
// 	}
//
// 	return ctx.HTMLBlob(http.StatusOK, responseHTML.Bytes())
// }

var templ = template.Must(template.ParseFS(webTemplates, "templates/*.templ"))

func renderTemplate(name string, lang contract.Language, pageData PageData, target io.Writer) error {
	templ, err := templ.Clone()
	if err != nil {
		return err
	}

	layoutTempl := templ.Lookup("layout")
	if layoutTempl == nil {
		return fmt.Errorf("could not find layout template")
	}
	bodyName := fmt.Sprintf("%s_%s", name, strings.ToLower(string(lang)))
	bodyTempl := templ.Lookup(bodyName)
	if bodyTempl == nil {
		return fmt.Errorf("could not find template %s", bodyName)
	}

	_, err = layoutTempl.AddParseTree("body", bodyTempl.Tree)
	if err != nil {
		return err
	}

	return layoutTempl.Execute(target, pageData)
}
