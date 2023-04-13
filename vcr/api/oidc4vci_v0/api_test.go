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

package oidc4vci_v0

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	httptest "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestWrapper_Routes(t *testing.T) {
	t.Run("API enabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().OIDC4VCIEnabled().Return(true)
		api := Wrapper{VCR: service}
		baseURL := httptest.StartEchoServer(t, func(router core.EchoRouter) {
			api.Routes(router)
		})

		httpResponse, err := http.Get(baseURL + "/identity/invalid-did/.well-known/openid-credential-wallet")

		require.NoError(t, err)
		// Assertion may look weird, but if we get this status code it means we entered the API function.
		assert.Equal(t, http.StatusBadRequest, httpResponse.StatusCode)
	})
	t.Run("API disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		service := vcr.NewMockVCR(ctrl)
		service.EXPECT().OIDC4VCIEnabled().Return(false)
		api := Wrapper{VCR: service}
		baseURL := httptest.StartEchoServer(t, func(router core.EchoRouter) {
			api.Routes(router)
		})

		httpResponse, err := http.Get(baseURL + "/identity/invalid-did/.well-known/openid-credential-wallet")

		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, httpResponse.StatusCode)
	})
}
