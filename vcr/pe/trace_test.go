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
	"strings"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core/to"
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

func Test_formatRejectionReason(t *testing.T) {
	jsonldVC := vcrTest.ValidNutsOrganizationCredential(t)
	jwtVC := vcrTest.JWTNutsOrganizationCredential(t, did.MustParseDID("did:web:example.com"))

	t.Run("JSON-LD credential against PD that requires JWT only", func(t *testing.T) {
		pdFormat := PresentationDefinitionClaimFormatDesignations{
			"jwt_vc": {"alg": []string{"EdDSA", "ES256"}},
		}
		reason := formatRejectionReason(&pdFormat, nil, jsonldVC)
		assert.Contains(t, reason, "format=ldp_vc")
		assert.Contains(t, reason, "proof_type=")
		assert.Contains(t, reason, "presentation definition accepts only formats")
		assert.Contains(t, reason, "jwt_vc")
	})

	t.Run("JSON-LD credential whose proof_type is not in the accepted list", func(t *testing.T) {
		pdFormat := PresentationDefinitionClaimFormatDesignations{
			"ldp_vc": {"proof_type": []string{"Ed25519Signature2020"}},
		}
		reason := formatRejectionReason(&pdFormat, nil, jsonldVC)
		assert.Contains(t, reason, "format=ldp_vc")
		assert.Contains(t, reason, "proof_type=JsonWebSignature2020")
		assert.Contains(t, reason, "requires ldp_vc proof_type in [Ed25519Signature2020]")
	})

	t.Run("JWT credential whose alg is not in the accepted list", func(t *testing.T) {
		pdFormat := PresentationDefinitionClaimFormatDesignations{
			"jwt_vc": {"alg": []string{"PS256"}},
		}
		reason := formatRejectionReason(&pdFormat, nil, jwtVC)
		assert.Contains(t, reason, "format=jwt_vc")
		assert.Contains(t, reason, "alg=") // exact alg depends on the test fixture; just confirm it's reported
		assert.Contains(t, reason, "requires jwt_vc alg in [PS256]")
	})

	t.Run("input descriptor format also reported when it rejects", func(t *testing.T) {
		idFormat := PresentationDefinitionClaimFormatDesignations{
			"jwt_vc": {"alg": []string{"EdDSA"}},
		}
		reason := formatRejectionReason(nil, &idFormat, jsonldVC)
		assert.Contains(t, reason, "input descriptor accepts only formats")
		assert.Contains(t, reason, "jwt_vc")
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

	// Expect exactly one debug log carrying the human-readable trace.
	var traceEntries []*logrus.Entry
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.DebugLevel && strings.HasPrefix(entry.Message, "PE: match evaluated") {
			traceEntries = append(traceEntries, entry)
		}
	}
	assert.Len(t, traceEntries, 1, "expected exactly one consolidated trace log entry")
	if len(traceEntries) == 0 {
		return
	}
	msg := traceEntries[0].Message
	assert.Contains(t, msg, "PE: match evaluated")
	assert.Contains(t, msg, "input descriptor")
	assert.Contains(t, msg, "considered=2")
	assert.Contains(t, msg, "matched=1")
	assert.Contains(t, msg, "selected=")
	assert.Contains(t, msg, "rejected "+nonMatchingID.String())
	assert.Contains(t, msg, "no value found at any of paths")
}

func TestMatchConstraints_DebugLogging_SubmissionRequirements(t *testing.T) {
	originalLogger := log.Logger().Logger
	originalLevel := originalLogger.Level
	hook := logTest.NewLocal(originalLogger)
	originalLogger.SetLevel(logrus.DebugLevel)
	t.Cleanup(func() {
		originalLogger.SetLevel(originalLevel)
		hook.Reset()
	})

	jsonldVC := vcrTest.ValidNutsOrganizationCredential(t)
	pd := PresentationDefinition{
		Id: "sr-trace-test",
		InputDescriptors: []*InputDescriptor{
			{
				Id:    "needs_org",
				Group: []string{"A"},
				Constraints: &Constraints{
					Fields: []Field{{Path: []string{"$.credentialSubject.organization.city"}}},
				},
			},
			{
				Id:    "needs_other",
				Group: []string{"B"},
				Constraints: &Constraints{
					Fields: []Field{{Path: []string{"$.someOtherField"}}},
				},
			},
		},
		SubmissionRequirements: []*SubmissionRequirement{
			{Name: "Group A required", Rule: "all", From: "A"},
			{Name: "Group B (pick at least 1)", Rule: "pick", From: "B", Min: to.Ptr(1)},
		},
	}

	_, _, _ = pd.Match([]vc.VerifiableCredential{jsonldVC})

	var msgs []string
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.DebugLevel && strings.HasPrefix(e.Message, "PE: match evaluated") {
			msgs = append(msgs, e.Message)
		}
	}
	assert.Len(t, msgs, 1, "expected exactly one consolidated trace log entry")
	if len(msgs) == 0 {
		return
	}
	msg := msgs[0]
	// Both submission requirements should be reported.
	assert.Contains(t, msg, `submission requirement "Group A required" rule=all from=A`)
	assert.Contains(t, msg, "available=1")
	assert.Contains(t, msg, ": satisfied")
	assert.Contains(t, msg, `submission requirement "Group B (pick at least 1)" rule=pick from=B min=1 available=0`)
	assert.Contains(t, msg, "not satisfied")
	assert.Contains(t, msg, "less matches (0) than minimal required (1)")
	// errors.Join newline must have been collapsed.
	assert.NotContains(t, msg, ": missing credentials\nsubmission")
}
