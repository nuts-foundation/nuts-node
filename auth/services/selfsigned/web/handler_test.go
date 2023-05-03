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
}

func TestHandler_RenderEmployeeIDDonePage(t *testing.T) {
}

func TestHandler_RenderEmployeeIDPage(t *testing.T) {
}

func TestHandler_Routes(t *testing.T) {
}

func TestNewHandler(t *testing.T) {
}

func Test_renderTemplate(t *testing.T) {
}
