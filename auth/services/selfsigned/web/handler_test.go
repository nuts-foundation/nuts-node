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
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"testing"
	"time"
)

func TestRenderTemplate(t *testing.T) {
	roleName := "Administrator"
	buf := new(bytes.Buffer)
	templates := NewTemplates()
	err := templates.Render("employee_identity", "nl", PageData{Session: types.Session{
		ExpiresAt: time.Now(),
		Contract:  "Hello, World!",
		Secret:    "secret",
		Status:    "pending",
		Employer:  "Darth Vader",
		Employee: types.Employee{
			Identifier: "johndoe@example.com",
			RoleName:   &roleName,
			Initials:   "J",
			FamilyName: "Doe",
		},
	}}, buf)
	require.NoError(t, err)
}

func TestHandler_HandleEmployeeIDForm(t *testing.T) {
	t.Run("ok - it sets status to completed and redirects to the done page", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)

		// expect a session load, not expired with a secret-value
		store.EXPECT().Load("123").Return(types.Session{
			Status:    types.SessionInProgress,
			ExpiresAt: time.Now().Add(1 * time.Minute),
			Secret:    "secret-value",
		}, true)
		// expect the update status call from in-progress to completed
		store.EXPECT().CheckAndSetStatus("123", types.SessionInProgress, types.SessionCompleted).Return(true)
		// mock form values
		mockContext.EXPECT().FormValue("accept").Return("true")
		mockContext.EXPECT().FormValue("secret").Return("secret-value")
		// expect redirect to done page
		mockContext.EXPECT().Redirect(http.StatusFound, fmt.Sprintf(donePagePathTemplate, "123"))

		h := NewHandler(store)
		err := h.HandleEmployeeIDForm(mockContext, "123")
		require.NoError(t, err)
	})

	t.Run("err - session not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{}, false)
		h := NewHandler(store)
		err := h.HandleEmployeeIDForm(mockContext, "123")
		require.Error(t, err)
		assert.EqualError(t, err, "code=404, message=session not found")
	})

	t.Run("err - expired session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:    types.SessionInProgress,
			ExpiresAt: time.Now().Add(-1 * time.Minute),
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionInProgress, types.SessionExpired).Return(true)
		h := NewHandler(store)
		err := h.HandleEmployeeIDForm(mockContext, "123")
		require.Error(t, err)
		assert.EqualError(t, err, "code=404, message=session expired")
	})

	t.Run("err - invalid secret sets session status to errored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:    types.SessionInProgress,
			ExpiresAt: time.Now().Add(1 * time.Minute),
			Secret:    "secret-value",
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionInProgress, types.SessionErrored).Return(true)
		mockContext.EXPECT().FormValue("accept").Return("true")
		mockContext.EXPECT().FormValue("secret").Return("invalid-secret")
		mockContext.EXPECT().Redirect(http.StatusFound, fmt.Sprintf(donePagePathTemplate, "123"))
		h := NewHandler(store)
		err := h.HandleEmployeeIDForm(mockContext, "123")
		assert.NoError(t, err)
	})

	t.Run("ok - cancelled session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:    types.SessionInProgress,
			ExpiresAt: time.Now().Add(1 * time.Minute),
			Secret:    "secret-value",
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionInProgress, types.SessionCancelled).Return(true)
		mockContext.EXPECT().FormValue("accept").Return("false")
		mockContext.EXPECT().FormValue("secret").Return("secret-value")
		mockContext.EXPECT().Redirect(http.StatusFound, fmt.Sprintf(donePagePathTemplate, "123"))
		h := NewHandler(store)
		err := h.HandleEmployeeIDForm(mockContext, "123")
		assert.NoError(t, err)
	})

	t.Run("err - session not in-progress", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:    types.SessionInProgress,
			ExpiresAt: time.Now().Add(1 * time.Minute),
			Secret:    "secret-value",
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionInProgress, types.SessionCompleted).Return(false)
		mockContext.EXPECT().FormValue("accept").Return("true")
		mockContext.EXPECT().FormValue("secret").Return("secret-value")

		h := NewHandler(store)
		err := h.HandleEmployeeIDForm(mockContext, "123")
		assert.EqualError(t, err, "code=404, message=no session with status in-progress found")
	})
}

func TestHandler_RenderEmployeeIDDonePage(t *testing.T) {
	validContractText := "NL:BehandelaarLogin:v3 Hierbij verklaar ik te handelen in naam van Zorg & Zo te A & B. Deze verklaring is geldig van woensdag, 1 januari 2020 02:01:01 tot woensdag, 1 januari 2020 03:01:01."

	// Test the RenderEmployeeIDDonePage function with a newly created session.
	// Expect a check for status for created and update to in-progress.
	// Expect a status 200 response with the rendered template.
	t.Run("ok - session found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:   types.SessionCreated,
			Contract: validContractText,
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionCreated, types.SessionInProgress).Return(true)
		mockContext.EXPECT().HTMLBlob(http.StatusOK, gomock.Any())
		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123")
		assert.NoError(t, err)
	})

	t.Run("err - session not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{}, false)
		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123")
		require.Error(t, err)
		assert.EqualError(t, err, "code=404, message=session not found")
	})

	t.Run("err - invalid contract text", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:   types.SessionCompleted,
			Contract: "invalid-contract-text",
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionCreated, types.SessionInProgress).Return(true)
		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid contract text: could not extract contract version, language and type")
	})
}

func TestHandler_RenderEmployeeIDPage(t *testing.T) {
	validContractText := "NL:BehandelaarLogin:v3 Hierbij verklaar ik te handelen in naam van Zorg & Zo te A & B. Deze verklaring is geldig van woensdag, 1 januari 2020 02:01:01 tot woensdag, 1 januari 2020 03:01:01."

	t.Run("ok - session found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:   types.SessionCreated,
			Contract: validContractText,
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionCreated, types.SessionInProgress).Return(true)
		// expect the form to be rendered
		mockContext.EXPECT().HTMLBlob(http.StatusOK, gomock.Any())

		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123")
		assert.NoError(t, err)
	})

	t.Run("err - session not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{}, false)
		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123")
		require.Error(t, err)
		assert.EqualError(t, err, "code=404, message=session not found")
	})

	t.Run("err - invalid contract text", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:   types.SessionInProgress,
			Contract: "invalid-contract-text",
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionCreated, types.SessionInProgress).Return(true)
		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123")
		require.Error(t, err)
		assert.EqualError(t, err, "invalid contract text: could not extract contract version, language and type")
	})

	// Test the RenderEmployeeIDPage function with a session that has the status completed
	// Expect a check for status for created which returns false.
	// Expect rendering the the done page with status 200
	t.Run("err - session.status not SessionCreated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:   types.SessionCompleted,
			Contract: validContractText,
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionCreated, types.SessionInProgress).Return(false)
		mockContext.EXPECT().HTMLBlob(http.StatusOK, gomock.Any())
		h := NewHandler(store)
		require.NoError(t, h.RenderEmployeeIDPage(mockContext, "123"))
	})
}

func TestHandler_Routes(t *testing.T) {
}

func Test_renderTemplate(t *testing.T) {
	templates := NewTemplates()
	t.Run("ok - all values are rendered in the template", func(t *testing.T) {
		roleName := "Nurse"
		s := PageData{Session: types.Session{
			Contract: "nl:logincontract:v1 contract string",
			Secret:   "secret value",
			Employee: types.Employee{
				Identifier: "123",
				RoleName:   &roleName,
				Initials:   "T",
				FamilyName: "Tester",
			},
		}}
		buf := new(bytes.Buffer)

		for _, lang := range []contract.Language{"en", "nl"} {
			err := templates.Render("employee_identity", lang, s, buf)

			assert.NoError(t, err)
			assert.Contains(t, buf.String(), "contract string")
			assert.Contains(t, buf.String(), s.Session.Secret, buf.String())
			assert.Contains(t, buf.String(), s.Session.Employee.Identifier)
			assert.Contains(t, buf.String(), *s.Session.Employee.RoleName)
			assert.Contains(t, buf.String(), s.Session.Employee.Initials)
			assert.Contains(t, buf.String(), s.Session.Employee.FamilyName)
		}
	})
	t.Run("ok - role name not present", func(t *testing.T) {
		s := PageData{Session: types.Session{
			Contract: "nl:logincontract:v1 contract string",
			Secret:   "secret value",
			Employee: types.Employee{
				Identifier: "123",
				Initials:   "T",
				FamilyName: "Tester",
			},
		}}
		for _, lang := range []contract.Language{"en", "nl"} {
			buf := new(bytes.Buffer)
			err := templates.Render("employee_identity", lang, s, buf)

			assert.NoError(t, err)
			assert.NotContains(t, buf.String(), "<td>Title</td>")
			assert.NotContains(t, buf.String(), "<td>Functieomschrijving</td>")
		}
	})

	t.Run("err - unknown template", func(t *testing.T) {
		buf := new(bytes.Buffer)
		err := templates.Render("employee_identity", "de", PageData{Session: types.Session{}}, buf)
		assert.EqualError(t, err, "could not find template employee_identity_de")
	})
}
