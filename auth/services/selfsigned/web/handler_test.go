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
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func TestRenderTemplate(t *testing.T) {
	buf := new(bytes.Buffer)
	err := renderTemplate("employee_identity", "nl", types.Session{
		ExpiresAt: time.Now(),
		Contract:  "Hello, World!",
		Secret:    "secret",
		Status:    "pending",
		Employer:  "Darth Vader",
		Employee: types.Employee{
			Identifier: "johndoe@example.com",
			RoleName:   "Administrator",
			Initials:   "J",
			FamilyName: "Doe",
		},
	}, buf)
	require.NoError(t, err)
	println(buf.String())
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
		err := h.HandleEmployeeIDForm(mockContext, "123", HandleEmployeeIDFormParams{})
		require.NoError(t, err)
	})

	t.Run("err - session not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{}, false)
		h := NewHandler(store)
		err := h.HandleEmployeeIDForm(mockContext, "123", HandleEmployeeIDFormParams{})
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
		err := h.HandleEmployeeIDForm(mockContext, "123", HandleEmployeeIDFormParams{})
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
		err := h.HandleEmployeeIDForm(mockContext, "123", HandleEmployeeIDFormParams{})
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
		err := h.HandleEmployeeIDForm(mockContext, "123", HandleEmployeeIDFormParams{})
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
		err := h.HandleEmployeeIDForm(mockContext, "123", HandleEmployeeIDFormParams{})
		assert.EqualError(t, err, "code=404, message=no session with status in-progress found")
	})
}

func TestHandler_RenderEmployeeIDDonePage(t *testing.T) {
	validContractText := "NL:BehandelaarLogin:v3 Hierbij verklaar ik te handelen in naam van Zorg & Zo te A & B. Deze verklaring is geldig van woensdag, 1 januari 2020 02:01:01 tot woensdag, 1 januari 2020 03:01:01."

	t.Run("ok - session found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:   types.SessionCompleted,
			Contract: validContractText,
		}, true)
		mockContext.EXPECT().HTMLBlob(http.StatusOK, gomock.Any())
		h := NewHandler(store)
		err := h.RenderEmployeeIDDonePage(mockContext, "123")
		assert.NoError(t, err)
	})

	t.Run("err - session not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{}, false)
		h := NewHandler(store)
		err := h.RenderEmployeeIDDonePage(mockContext, "123")
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
		h := NewHandler(store)
		err := h.RenderEmployeeIDDonePage(mockContext, "123")
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
			Status:   types.SessionInProgress,
			Contract: validContractText,
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionCreated, types.SessionInProgress).Return(true)
		// expect the form to be rendered
		mockContext.EXPECT().HTMLBlob(http.StatusOK, gomock.Any())

		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123", RenderEmployeeIDPageParams{})
		assert.NoError(t, err)
	})

	t.Run("err - session not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{}, false)
		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123", RenderEmployeeIDPageParams{})
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
		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123", RenderEmployeeIDPageParams{})
		require.Error(t, err)
		assert.EqualError(t, err, "invalid contract text: could not extract contract version, language and type")
	})

	t.Run("err - session status not created", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := types.NewMockSessionStore(ctrl)
		mockContext := mock.NewMockContext(ctrl)
		store.EXPECT().Load("123").Return(types.Session{
			Status:   types.SessionCompleted,
			Contract: validContractText,
		}, true)
		store.EXPECT().CheckAndSetStatus("123", types.SessionCreated, types.SessionInProgress).Return(false)
		h := NewHandler(store)
		err := h.RenderEmployeeIDPage(mockContext, "123", RenderEmployeeIDPageParams{})
		require.Error(t, err)
		assert.EqualError(t, err, "code=404, message=no session with status created found")
	})
}

func TestHandler_Routes(t *testing.T) {
}

func Test_renderTemplate(t *testing.T) {
	t.Run("ok - all values are rendered in the template", func(t *testing.T) {
		s := types.Session{
			Contract: "nl:logincontract:v1 contract string",
			Secret:   "secret value",
			Employee: types.Employee{
				Identifier: "123",
				RoleName:   "Nurse",
				Initials:   "T",
				FamilyName: "Tester",
			},
		}
		for _, lang := range []contract.Language{"en", "nl"} {
			buf := new(bytes.Buffer)
			err := renderTemplate("employee_identity", lang, s, buf)

			assert.NoError(t, err)
			assert.Contains(t, buf.String(), "contract string")
			assert.Contains(t, buf.String(), s.Secret, buf.String())
			assert.Contains(t, buf.String(), s.Employee.Identifier)
			assert.Contains(t, buf.String(), s.Employee.RoleName)
			assert.Contains(t, buf.String(), s.Employee.Initials)
			assert.Contains(t, buf.String(), s.Employee.FamilyName)
		}
	})

	t.Run("err - unknown template", func(t *testing.T) {
		buf := new(bytes.Buffer)
		err := renderTemplate("employee_identity", "de", types.Session{}, buf)
		assert.EqualError(t, err, "template: pattern matches no files: `templates/employee_identity_de.html`")
	})
}
