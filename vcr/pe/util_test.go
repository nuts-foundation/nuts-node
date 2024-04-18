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

package pe

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseEnvelope(t *testing.T) {
	t.Run("JWT", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, did.MustParseDID("did:example:1"), nil, test.ValidNutsOrganizationCredential(t))
		envelope, err := ParseEnvelope([]byte(presentation.Raw()))
		require.NoError(t, err)
		require.Equal(t, presentation.ID.String(), envelope.asInterface.(map[string]interface{})["id"])
		require.Len(t, envelope.Presentations, 1)
	})
	t.Run("invalid JWT", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`eyINVALID`))
		assert.EqualError(t, err, "unable to parse PEX envelope as verifiable presentation: invalid JWT")
		assert.Nil(t, envelope)
	})
	t.Run("JSON object", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`{"id": "value"}`))
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"id": "value"}, envelope.asInterface)
		require.Len(t, envelope.Presentations, 1)
	})
	t.Run("invalid VP as JSON object", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`{"id": true}`))
		assert.ErrorContains(t, err, "unable to parse PEX envelope as verifiable presentation")
		assert.Nil(t, envelope)
	})
	t.Run("JSON array with objects", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`[{"id": "value"}]`))
		require.NoError(t, err)
		require.Equal(t, []interface{}{map[string]interface{}{"id": "value"}}, envelope.asInterface)
		require.Len(t, envelope.Presentations, 1)
	})
	t.Run("JSON array with JWTs", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, did.MustParseDID("did:example:1"), nil, test.ValidNutsOrganizationCredential(t))
		presentations := []string{presentation.Raw(), presentation.Raw()}
		listJSON, _ := json.Marshal(presentations)
		envelope, err := ParseEnvelope(listJSON)
		require.NoError(t, err)
		require.Len(t, envelope.asInterface, 2)
		require.Len(t, envelope.Presentations, 2)
	})
	t.Run("invalid VPs list as JSON", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`[{"id": true}]`))
		assert.ErrorContains(t, err, "unable to parse PEX envelope as verifiable presentation")
		assert.Nil(t, envelope)
	})
	t.Run("invalid format", func(t *testing.T) {
		envelope, err := ParseEnvelope([]byte(`true`))
		assert.EqualError(t, err, "unable to parse PEX envelope as verifiable presentation: invalid JWT")
		assert.Nil(t, envelope)
	})
}

func TestEnvelope_JSONMarshalling(t *testing.T) {
	t.Run("JWT (marshalled as string)", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, did.MustParseDID("did:example:1"), nil, test.ValidNutsOrganizationCredential(t))
		expected := presentation.Raw()

		envelope, err := ParseEnvelope([]byte(expected))
		require.NoError(t, err)
		asJSON, err := json.Marshal(envelope)
		require.NoError(t, err)
		err = json.Unmarshal(asJSON, &envelope)
		require.NoError(t, err)

		require.Equal(t, expected, string(envelope.raw))
	})
	t.Run("JSON object", func(t *testing.T) {
		expected := `{"id": "value"}`

		envelope, err := ParseEnvelope([]byte(expected))
		require.NoError(t, err)
		asJSON, err := json.Marshal(envelope)
		require.NoError(t, err)
		err = json.Unmarshal(asJSON, &envelope)
		require.NoError(t, err)

		require.JSONEq(t, expected, string(envelope.raw))
	})
	t.Run("JSON array", func(t *testing.T) {
		presentation, _ := test.CreateJWTPresentation(t, did.MustParseDID("did:example:1"), nil, test.ValidNutsOrganizationCredential(t))
		presentations := []string{presentation.Raw(), presentation.Raw()}
		expected, _ := json.Marshal(presentations)

		envelope, err := ParseEnvelope(expected)
		require.NoError(t, err)
		asJSON, err := json.Marshal(envelope)
		require.NoError(t, err)
		err = json.Unmarshal(asJSON, &envelope)
		require.NoError(t, err)

		require.JSONEq(t, string(expected), string(envelope.raw))
	})
}
