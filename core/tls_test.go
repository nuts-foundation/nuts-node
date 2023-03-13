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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadTrustStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		store, err := LoadTrustStore("../network/test/truststore.pem")

		assert.NoError(t, err)
		assert.NotNil(t, store)
		assert.Len(t, store.Certificates(), 4)

		// Assert root certs
		assert.Len(t, store.RootCAs, 2)
		assert.Equal(t, "CN=Root CA", store.RootCAs[0].Subject.String())
		assert.Equal(t, "CN=Staat der Nederlanden EV Root CA,O=Staat der Nederlanden,C=NL", store.RootCAs[1].Subject.String())
		// Assert intermediate certs
		assert.Len(t, store.IntermediateCAs, 2)
		assert.Equal(t, "CN=Staat der Nederlanden Domein Server CA 2020,O=Staat der Nederlanden,C=NL", store.IntermediateCAs[1].Subject.String())
	})
	t.Run("invalid PEM file", func(t *testing.T) {
		store, err := LoadTrustStore("tls_test.go")
		assert.Error(t, err)
		assert.Nil(t, store)
	})
}
