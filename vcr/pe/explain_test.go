/*
 * Copyright (C) 2026 Nuts community
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
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	vcrTest "github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/sirupsen/logrus"
	logTest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func Test_explainFieldMismatch(t *testing.T) {
	credential := map[string]interface{}{
		"issuer": "did:web:foo",
	}

	t.Run("no value found at any path", func(t *testing.T) {
		field := Field{Path: []string{"$.missing"}}
		reason := explainFieldMismatch(field, credential)
		assert.Contains(t, reason, "no value found at any of paths")
	})

	t.Run("filter rejects", func(t *testing.T) {
		fieldID := "iss"
		want := "did:web:bar"
		field := Field{
			Id:     &fieldID,
			Path:   []string{"$.issuer"},
			Filter: &Filter{Type: "string", Const: &want},
		}
		reason := explainFieldMismatch(field, credential)
		assert.Contains(t, reason, "did:web:foo")
		assert.Contains(t, reason, "did:web:bar")
		assert.Contains(t, reason, `field "iss"`)
	})

	t.Run("matching field returns empty reason", func(t *testing.T) {
		want := "did:web:foo"
		field := Field{
			Path:   []string{"$.issuer"},
			Filter: &Filter{Type: "string", Const: &want},
		}
		assert.Empty(t, explainFieldMismatch(field, credential))
	})

	t.Run("optional field with no value returns empty reason", func(t *testing.T) {
		optional := true
		field := Field{
			Optional: &optional,
			Path:     []string{"$.missing"},
		}
		assert.Empty(t, explainFieldMismatch(field, credential))
	})
}

func TestMatchConstraints_DebugLogging(t *testing.T) {
	pd := definitions().JSONLD
	matchingVC := vcrTest.ValidNutsOrganizationCredential(t)
	nonMatchingID := ssi.MustParseURI("urn:test:non-matching")
	nonMatchingVC := vc.VerifiableCredential{
		Type:              []ssi.URI{ssi.MustParseURI("VerifiableCredential")},
		ID:                &nonMatchingID,
		CredentialSubject: []map[string]any{{"id": "did:example:bob"}},
	}

	originalLogger := log.Logger().Logger
	originalLevel := originalLogger.Level
	hook := logTest.NewLocal(originalLogger)
	originalLogger.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() {
		originalLogger.SetLevel(originalLevel)
		hook.Reset()
	})

	_, _, _ = pd.Match([]vc.VerifiableCredential{nonMatchingVC, matchingVC})

	// Expect at least one rejection log and one descriptor-evaluated log.
	var rejectionFound, summaryFound bool
	for _, entry := range hook.AllEntries() {
		if entry.Level != logrus.DebugLevel {
			continue
		}
		switch entry.Message {
		case "PE: credential rejected":
			rejectionFound = true
			assert.NotEmpty(t, entry.Data["reason"])
			assert.NotEmpty(t, entry.Data["input_descriptor"])
		case "PE: input descriptor evaluated":
			summaryFound = true
			assert.NotEmpty(t, entry.Data["input_descriptor"])
		}
	}
	assert.True(t, rejectionFound, "expected a 'credential rejected' debug log")
	assert.True(t, summaryFound, "expected a 'input descriptor evaluated' debug log")
}
