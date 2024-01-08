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

package policy

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/policy/api/v1/client"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
)

func TestRouter_Configure(t *testing.T) {
	t.Run("ok - directory is set", func(t *testing.T) {
		router := Router{}

		cfg := router.Config().(*Config)
		cfg.Directory = "test"
		err := router.Configure(core.ServerConfig{})

		assert.NoError(t, err)
		_, ok := router.backend.(*localPDP)
		assert.True(t, ok)
	})
	t.Run("ok - address is set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		pki := pki.NewMockProvider(ctrl)
		pki.EXPECT().CreateTLSConfig(gomock.Any()).Return(nil, nil)
		router := Router{
			pkiInstance: pki,
		}

		cfg := router.Config().(*Config)
		cfg.Address = "http://localhost:8080"
		err := router.Configure(core.ServerConfig{})

		assert.NoError(t, err)
		_, ok := router.backend.(*remote)
		assert.True(t, ok)
	})
	t.Run("err - both directory and address are set", func(t *testing.T) {
		router := Router{}

		cfg := router.Config().(*Config)
		cfg.Directory = "test"
		cfg.Address = "test"
		err := router.Configure(core.ServerConfig{})

		assert.EqualError(t, err, "both policy.directory and policy.address are set, please choose one")
	})

	t.Run("err - directory doesn't exist", func(t *testing.T) {
		router := Router{}

		cfg := router.Config().(*Config)
		cfg.Directory = "unknown"
		err := router.Configure(core.ServerConfig{})

		assert.EqualError(t, err, "failed to load policy from directory: open unknown: no such file or directory")
	})

	t.Run("err - address is invalid", func(t *testing.T) {
		router := Router{}

		cfg := router.Config().(*Config)
		cfg.Address = "://"
		err := router.Configure(core.ServerConfig{})

		assert.EqualError(t, err, "failed to parse policy.address: parse \"://\": missing protocol scheme")
	})
}

func TestRouter_Name(t *testing.T) {
	router := Router{}

	assert.Equal(t, ModuleName, router.Name())
}

func TestRouterForwarding(t *testing.T) {
	ctrl := gomock.NewController(t)
	ctx := context.Background()
	testDID := did.MustParseDID("did:web:example.com:test")
	presentationDefinition := pe.PresentationDefinition{}
	router := Router{
		backend: NewMockBackend(ctrl),
	}

	t.Run("Authorized", func(t *testing.T) {
		router.backend.(*MockBackend).EXPECT().Authorized(ctx, gomock.Any()).Return(true, nil)

		result, err := router.Authorized(ctx, client.AuthorizedRequest{})

		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("PresentationDefinition", func(t *testing.T) {
		router.backend.(*MockBackend).EXPECT().PresentationDefinition(ctx, testDID, "test").Return(&presentationDefinition, nil)

		result, err := router.PresentationDefinition(ctx, testDID, "test")

		require.NoError(t, err)
		assert.Equal(t, presentationDefinition, *result)
	})
}
