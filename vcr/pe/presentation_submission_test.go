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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParsePresentationSubmission(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		submission, err := ParsePresentationSubmission([]byte(`{"id": "1", "definition_id":"1", "descriptor_map": []}`))
		require.NoError(t, err)
		assert.Equal(t, "1", submission.Id)
	})
	t.Run("missing id", func(t *testing.T) {
		_, err := ParsePresentationSubmission([]byte(`{"definition_id":"1", "descriptor_map": []}`))
		assert.ErrorContains(t, err, `missing properties: "id"`)
	})
}

func TestPresentationSubmissionBuilder_Build(t *testing.T) {
	holder1 := did.MustParseDID("did:example:1")
	holder2 := did.MustParseDID("did:example:2")
	id1 := ssi.MustParseURI("1")
	id2 := ssi.MustParseURI("2")
	vc1 := vc.VerifiableCredential{ID: &id1}
	vc2 := vc.VerifiableCredential{ID: &id2}

	t.Run("ok - single wallet", func(t *testing.T) {
		presentationDefinition := PresentationDefinition{}
		_ = json.Unmarshal([]byte(test.All), &presentationDefinition)
		builder := presentationDefinition.Builder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vc1, vc2})

		submission, signInstructions, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		require.NotNil(t, signInstructions)
		assert.Len(t, signInstructions, 1)
		assert.Len(t, submission.DescriptorMap, 1)
		assert.Equal(t, "$.", submission.DescriptorMap[0].Path)
		require.Len(t, submission.DescriptorMap[0].PathNested, 2)
		assert.Equal(t, "$.verifiableCredential[0]", submission.DescriptorMap[0].PathNested[0].Path)
	})
	t.Run("ok - two wallets", func(t *testing.T) {
		presentationDefinition := PresentationDefinition{}
		_ = json.Unmarshal([]byte(test.All), &presentationDefinition)
		builder := presentationDefinition.Builder()
		builder.AddWallet(holder1, []vc.VerifiableCredential{vc1})
		builder.AddWallet(holder2, []vc.VerifiableCredential{vc2})

		submission, signInstructions, err := builder.Build("ldp_vp")

		require.NoError(t, err)
		require.NotNil(t, signInstructions)
		assert.Len(t, signInstructions, 2)
		assert.Len(t, submission.DescriptorMap, 2)
		assert.Equal(t, "$[0]", submission.DescriptorMap[0].Path)
		require.Len(t, submission.DescriptorMap[0].PathNested, 1)
		assert.Equal(t, "$.verifiableCredential[0]", submission.DescriptorMap[0].PathNested[0].Path)
		assert.Equal(t, "$[1]", submission.DescriptorMap[1].Path)
		require.Len(t, submission.DescriptorMap[1].PathNested, 1)
		assert.Equal(t, "$.verifiableCredential[0]", submission.DescriptorMap[1].PathNested[0].Path)
	})
}
