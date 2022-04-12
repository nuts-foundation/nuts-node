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
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/store"

	"github.com/stretchr/testify/assert"
)

func TestAuth_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		os.Setenv("NUTS_NETWORK_ENABLETLS", "false")
		defer os.Unsetenv("NUTS_NETWORK_ENABLETLS")
		i := NewTestAuthInstance(t)
		_ = i.Configure(*core.NewServerConfig())
	})

	t.Run("ok - TLS files loaded", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.TrustStoreFile = "test/certs/ca.pem"
		authCfg.CertKeyFile = "test/certs/example.com.key"
		authCfg.CertFile = "test/certs/example.com.pem"
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, i.tlsConfig)
	})

	t.Run("ok - TLS is properly configured", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.CertKeyFile = "test/certs/example.com.key"
		authCfg.CertFile = "test/certs/example.com.pem"
		authCfg.TrustStoreFile = "test/certs/ca.pem"

		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		assert.NoError(t, err)

		assert.Equal(t, core.MinTLSVersion, i.TLSConfig().MinVersion)
	})

	t.Run("error - no publicUrl", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.IrmaSchemeManager = "pbdf"
		i := testInstance(t, authCfg)
		cfg := core.NewServerConfig()
		cfg.Strictmode = true
		assert.Equal(t, ErrMissingPublicURL, i.Configure(*cfg))
	})

	t.Run("error - IRMA config failure", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.IrmaSchemeManager = "non-existing"
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - IRMA scheme manager not set", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.IrmaSchemeManager = ""
		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		assert.EqualError(t, err, "IRMA SchemeManager must be set")
	})

	t.Run("error - only 'pbdf' IRMA scheme manager allow in strict mode", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.IrmaSchemeManager = "demo"
		i := testInstance(t, authCfg)
		serverConfig := core.NewServerConfig()
		serverConfig.Strictmode = true
		err := i.Configure(*serverConfig)
		assert.EqualError(t, err, "in strictmode the only valid irma-scheme-manager is 'pbdf'")
	})

	t.Run("error - TLS required in strict mode", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.PublicURL = "https://example.com"
		i := testInstance(t, authCfg)
		serverConfig := core.NewServerConfig()
		serverConfig.Strictmode = true
		err := i.Configure(*serverConfig)
		assert.EqualError(t, err, "in strictmode TLS must be enabled")
	})

	t.Run("error - unknown truststore when TLS enabled", func(t *testing.T) {
		authCfg := TestConfig()
		authCfg.CertKeyFile = "test/certs/example.com.key"
		authCfg.CertFile = "test/certs/example.com.pem"
		authCfg.TrustStoreFile = "non-existing"

		i := testInstance(t, authCfg)
		err := i.Configure(*core.NewServerConfig())
		assert.EqualError(t, err, "unable to read trust store (file=non-existing): open non-existing: no such file or directory")
	})
}

func testInstance(t *testing.T, cfg Config) *Auth {
	cryptoInstance := crypto.NewTestCryptoInstance()
	vcrInstance := vcr.NewTestVCRInstance(t)
	return NewAuthInstance(cfg, store.NewMemoryStore(), vcrInstance, cryptoInstance, nil, nil)
}

func TestAuth_Name(t *testing.T) {
	assert.Equal(t, "Auth", (&Auth{}).Name())
}

func TestAuth_Config(t *testing.T) {
	assert.Equal(t, Config{}, *(&Auth{}).Config().(*Config))
}
