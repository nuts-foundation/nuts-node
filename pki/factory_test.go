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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCreateTLSConfig(t *testing.T) {
	cfg := core.NewServerConfig().TLS
	cfg.TrustStoreFile = "test/truststore.pem"
	cfg.CertFile = "test/A-valid.pem"
	cfg.CertKeyFile = "test/A-valid.pem"

	validator, tlsConfig, err := CreateTLSConfig(cfg)

	require.NoError(t, err)
	assert.NotNil(t, validator)
	require.NotNil(t, tlsConfig)
	assert.NotNil(t, tlsConfig.VerifyPeerCertificate)
	assert.Equal(t, core.MinTLSVersion, tlsConfig.MinVersion)
	assert.NotEmpty(t, tlsConfig.Certificates)
	assert.NotNil(t, tlsConfig.RootCAs)
}
