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

package oidc4vci

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func Test_httpOAuth2Client_RequestAccessToken(t *testing.T) {
	httpClient := &http.Client{}
	params := map[string]string{"some-param": "some-value"}
	t.Run("ok", func(t *testing.T) {
		setup := setupClientTest(t)
		result, err := (&httpOAuth2Client{
			metadata:   *setup.providerMetadata,
			httpClient: httpClient,
		}).RequestAccessToken("some-grant-type", params)

		assert.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, result.AccessToken)
		require.Len(t, setup.requests, 1)
		require.Equal(t, "application/x-www-form-urlencoded", setup.requests[0].Header.Get("Content-Type"))
	})
	t.Run("error", func(t *testing.T) {
		setup := setupClientTest(t)
		setup.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		result, err := (&httpOAuth2Client{
			metadata:   *setup.providerMetadata,
			httpClient: httpClient,
		}).RequestAccessToken("some-grant-type", params)

		require.ErrorContains(t, err, "request access token error")
		assert.Nil(t, result)
	})
}
