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

package pki

import (
	"context"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_New(t *testing.T) {
	e := New()

	assert.IsType(t, &PKI{}, e)
	assert.Equal(t, DefaultConfig(), e.config)
	assert.Nil(t, e.validator)
}

func TestPKI_Name(t *testing.T) {
	e := New()
	assert.Equal(t, "PKI", e.Name())
}

func TestPKI_Config(t *testing.T) {
	e := New()

	cfgPtr := e.Config()

	assert.Same(t, &e.config, cfgPtr)
	assert.IsType(t, Config{}, e.config)
}

func TestPKI_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		e := New()

		err := e.Configure(core.ServerConfig{})

		assert.NoError(t, err)
		assert.NotNil(t, e.validator)
	})
	t.Run("invalid config", func(t *testing.T) {
		e := New()
		e.config.Denylist = DenylistConfig{
			URL:           "example.com",
			TrustedSigner: "definitely not valid",
		}

		err := e.Configure(core.ServerConfig{})

		assert.Error(t, err)
	})
}

func TestPKI_Runnable(t *testing.T) {
	e := New()
	e.validator = &validator{}

	assert.Nil(t, e.ctx)
	assert.Nil(t, e.shutdown)

	err := e.Start()
	defer e.shutdown() // prevent go routine leak in the validator

	assert.NoError(t, err)
	assert.NotNil(t, e.ctx)
	assert.NotNil(t, e.shutdown)

	err = e.Shutdown()

	assert.NoError(t, err)
	assert.ErrorIs(t, e.ctx.Err(), context.Canceled)
}

func TestPKI_CheckHealth(t *testing.T) {
	// Create Engine
	e := New()
	require.NoError(t, e.Configure(core.ServerConfig{}))

	// Add truststore
	store, err := core.LoadTrustStore(truststore) // contains 1 CRL distribution point
	require.NoError(t, err)
	require.NoError(t, e.validator.AddTruststore(store.Certificates()))

	// Add Denylist
	testServer := denylistTestServer(t, "")
	e.denylist, err = testDenylist(testServer.URL, publicKeyDoNotUse)
	require.NoError(t, err)
	require.NotNil(t, e.denylist)

	t.Run("ok", func(t *testing.T) {
		// Set time to zero to match non-updated crls/denylist. This works because crls for issuers not valid at nowFunc() are not checked
		nowFunc = func() time.Time {
			return time.Time{}.Add(time.Hour)
		}
		defer func() { nowFunc = time.Now }()

		results := e.CheckHealth()
		assert.Len(t, results, 1)

		status := results[healthCRL]
		require.NotNil(t, status)
		assert.Equal(t, core.HealthStatusUp, status.Status)
		assert.Nil(t, status.Details)
	})

	t.Run("crl + denylist outdated", func(t *testing.T) {
		nowFunc = func() time.Time {
			return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		defer func() { nowFunc = time.Now }()

		// Check health
		results := e.CheckHealth()
		assert.Len(t, results, 2)

		// validate healthCRL
		statusCRL := results[healthCRL]
		require.NotNil(t, statusCRL)
		require.Equal(t, core.HealthStatusDown, statusCRL.Status)
		detailsCrl := statusCRL.Details.([]outdatedCRL)
		assert.Len(t, detailsCrl, 1)
		assert.Equal(t, outdatedCRL{
			Issuer:      "CN=Root CA,O=Nuts Foundation,C=NL",
			Endpoint:    "http://certs.nuts.nl/RootCALatest.crl",
			LastUpdated: time.Time{},
		}, detailsCrl[0])

		// validate healthDenylist
		statusDenylist := results[healthDenylist]
		require.NotNil(t, statusDenylist)
		assert.Equal(t, core.HealthStatusDown, statusDenylist.Status)
		assert.Equal(t, outdatedCRL{
			Issuer:      "denylist",
			Endpoint:    testServer.URL,
			LastUpdated: time.Time{},
		}, statusDenylist.Details)
	})
}

func TestPKI_CreateTLSConfig(t *testing.T) {
	t.Run("TLS enabled", func(t *testing.T) {
		e := New()
		require.NoError(t, e.Configure(core.ServerConfig{}))
		cfg := core.NewServerConfig().TLS
		cfg.TrustStoreFile = "test/truststore.pem"
		cfg.CertFile = "test/A-valid.pem"
		cfg.CertKeyFile = "test/A-valid.pem"

		tlsConfig, err := e.CreateTLSConfig(cfg)

		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		assert.NotNil(t, tlsConfig.VerifyPeerCertificate)
		assert.Equal(t, core.MinTLSVersion, tlsConfig.MinVersion)
		assert.NotEmpty(t, tlsConfig.Certificates)
		assert.NotNil(t, tlsConfig.RootCAs)
		// Assert the certificate in truststore.pem was loaded into the truststore
		_, ok := e.truststore.Load("CN=Intermediate A CA")
		assert.True(t, ok)
	})
	t.Run("TLS disabled", func(t *testing.T) {
		e := New()
		require.NoError(t, e.Configure(core.ServerConfig{}))
		tlsConfig, err := e.CreateTLSConfig(core.NewServerConfig().TLS)

		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})
}
