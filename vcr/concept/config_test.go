/*
 * Nuts node
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

package concept

import (
	"testing"

	vc2 "github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
)

func TestConfig_transform(t *testing.T) {
	t.Run("without template raw VC is returned", func(t *testing.T) {
		config := Config{}
		vc := vc2.VerifiableCredential{
			CredentialSubject: []interface{}{
				map[string]string{"key": "value"},
			},
		}

		transformed, err := config.transform(vc)

		if !assert.NoError(t, err) {
			return
		}

		subject, ok := transformed["credentialSubject"].(map[string]interface{})
		if !assert.True(t, ok) {
			return
		}

		assert.Equal(t, "value", subject["key"])
	})
}
