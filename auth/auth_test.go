/*
 * Copyright (C) 2021 Nuts community
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

package auth

import (
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr"
	"go.uber.org/mock/gomock"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth_Configure(t *testing.T) {
	tlsServerConfig := *core.NewServerConfig()
	tlsServerConfig.URL = "https://nuts.nl"
	tlsServerConfig.TLS.TrustStoreFile = "test/certs/ca.pem"
	tlsServerConfig.TLS.CertKeyFile = "test/certs/example.com.key"
	tlsServerConfig.TLS.CertFile = "test/certs/example.com.pem"

	t.Run("ok", func(t *testing.T) {
		config := DefaultConfig()
		config.ContractValidators = []string{"dummy"}
		ctrl := gomock.NewController(t)
		pkiMock := pki.NewMockProvider(ctrl)
		pkiMock.EXPECT().CreateTLSConfig(gomock.Any()) // tlsConfig
		vdrInstance := vdr.NewMockVDR(ctrl)
		vdrInstance.EXPECT().Resolver().AnyTimes()

		i := NewAuthInstance(config, vdrInstance, vcr.NewTestVCRInstance(t), crypto.NewMemoryCryptoInstance(), nil, nil, pkiMock)

		require.NoError(t, i.Configure(tlsServerConfig))
	})
	t.Run("use legacy auth.http.timeout config", func(t *testing.T) {
		config := DefaultConfig()
		config.HTTPTimeout = 10
		config.ContractValidators = []string{"dummy"}
		ctrl := gomock.NewController(t)
		pkiMock := pki.NewMockProvider(ctrl)
		pkiMock.EXPECT().CreateTLSConfig(gomock.Any()) // tlsConfig
		vdrInstance := vdr.NewMockVDR(ctrl)
		vdrInstance.EXPECT().Resolver().AnyTimes()

		i := NewAuthInstance(config, vdrInstance, vcr.NewTestVCRInstance(t), crypto.NewMemoryCryptoInstance(), nil, nil, pkiMock)

		require.NoError(t, i.Configure(tlsServerConfig))
	})

	t.Run("error - IRMA config failure", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.Irma.SchemeManager = "non-existing"
		serverConfig := tlsServerConfig
		serverConfig.Strictmode = false
		i := testInstance(t, authCfg)
		err := i.Configure(serverConfig)
		require.NoError(t, err)
	})

	t.Run("error - IRMA scheme manager not set", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.Irma.SchemeManager = ""
		i := testInstance(t, authCfg)
		err := i.Configure(tlsServerConfig)
		assert.EqualError(t, err, "IRMA SchemeManager must be set")
	})

	t.Run("error - only 'pbdf' IRMA scheme manager allow in strict mode", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.Irma.SchemeManager = "demo"
		i := testInstance(t, authCfg)
		err := i.Configure(tlsServerConfig)
		assert.EqualError(t, err, "in strictmode the only valid irma-scheme-manager is 'pbdf'")
	})

	t.Run("error - TLS config provider returns error", func(t *testing.T) {
		i := testInstance(t, TestConfig())
		pkiProvider := pki.NewMockProvider(gomock.NewController(t))
		i.pkiProvider = pkiProvider
		pkiProvider.EXPECT().CreateTLSConfig(gomock.Any()).Return(nil, assert.AnError)
		err := i.Configure(tlsServerConfig)
		assert.ErrorIs(t, err, assert.AnError)
	})
}

func TestAuth_Name(t *testing.T) {
	assert.Equal(t, "Auth", (&Auth{}).Name())
}

func TestAuth_Config(t *testing.T) {
	assert.Equal(t, Config{}, *(&Auth{}).Config().(*Config))
}
