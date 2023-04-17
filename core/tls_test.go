/*
 * Copyright (C) 2022 Nuts community
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

package core

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestLoadTrustStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		nowFunc = func() time.Time { return time.Date(2022, 12, 1, 0, 0, 0, 0, time.UTC) }
		defer func() { nowFunc = time.Now }()
		store, err := LoadTrustStore("../pki/test/pkioverheid-server-bundle.pem")

		require.NoError(t, err)
		assert.NotNil(t, store)
		assert.Len(t, store.Certificates(), 3)

		// Assert root certs
		require.Len(t, store.RootCAs, 1)
		assert.Equal(t, "CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL", store.RootCAs[0].Subject.String())
		// Assert intermediate certs
		require.Len(t, store.IntermediateCAs, 2)
		assert.Equal(t, "CN=Staat der Nederlanden Domein Server CA 2020,O=Staat der Nederlanden,C=NL", store.IntermediateCAs[1].Subject.String())
	})
	t.Run("invalid PEM file", func(t *testing.T) {
		store, err := LoadTrustStore("tls_test.go")
		assert.Error(t, err)
		assert.Nil(t, store)
	})
	t.Run("incomplete chain", func(t *testing.T) {
		leafCert, err := os.ReadFile("../test/pki/certificate-and-key.pem")
		cert, err := ParseCertificates(leafCert)
		require.NoError(t, err)

		err = validate(&TrustStore{certificates: cert})

		assert.EqualError(t, err, "x509: certificate signed by unknown authority")
	})
}
