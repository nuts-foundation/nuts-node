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

package jsonld

import (
	"encoding/json"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
)

func TestNewJSONLDInstance(t *testing.T) {
	instance := NewJSONLDInstance()
	t.Run("it creates a new JSONLD instance", func(t *testing.T) {
		assert.Implements(t, (*JSONLD)(nil), instance)
	})

	t.Run("it implements the Named interface", func(t *testing.T) {
		assert.Implements(t, (*core.Named)(nil), instance)
	})

	t.Run("it implements the Injectable interface", func(t *testing.T) {
		assert.Implements(t, (*core.Injectable)(nil), instance)
	})

	t.Run("as an injectable", func(t *testing.T) {
		injectable := instance.(core.Injectable)
		t.Run("it knows its name", func(t *testing.T) {
			assert.Equal(t, "JSONLD", injectable.Name())
		})

		t.Run("it returns its config", func(t *testing.T) {
			config := injectable.Config()
			assert.IsType(t, &Config{}, config)
			jsonldConfig := config.(*Config)
			assert.Len(t, jsonldConfig.Contexts.LocalFileMapping, 5)
		})

		t.Run("as an configurable", func(t *testing.T) {
			configurable := instance.(core.Configurable)

			t.Run("it can be configured", func(t *testing.T) {
				assert.NoError(t, configurable.Configure(*core.NewServerConfig()))
				assert.NotNil(t, instance.DocumentLoader())
			})
		})

	})
}

func TestAllFieldsDefined(t *testing.T) {
	documentLoader := NewTestJSONLDManager(t).DocumentLoader()
	t.Run("ok - vc", func(t *testing.T) {
		assert.NoError(t, AllFieldsDefined(documentLoader, []byte(TestOrganizationCredential)))
	})
	t.Run("ok - vp", func(t *testing.T) {
		assert.NoError(t, AllFieldsDefined(documentLoader, []byte(testVP)))
	})
	t.Run("failed - invalid fields", func(t *testing.T) {
		var invalidCredentialSubject = make(map[string]interface{})
		invalidCredentialSubject["id"] = "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY"
		invalidCredentialSubject["organizationButIncorrectFieldName"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": "EIbergen",
		}

		inputVC := testOrganizationCredential()
		inputVC.CredentialSubject[0] = invalidCredentialSubject
		// inputVC.raw is only set during unmarshal, so we need to set
		vcBytes, _ := json.Marshal(inputVC)

		err := AllFieldsDefined(documentLoader, vcBytes)

		assert.EqualError(t, err, "jsonld: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
	})

}
