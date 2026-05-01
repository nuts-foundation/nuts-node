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
		// Pin the JWT fixture's alg so the test fails loudly if the helper changes its alg.
		// JWTNutsOrganizationCredential signs with ES384.
		reason := formatRejectionReason(&pdFormat, nil, jwtVC)
		assert.Contains(t, reason, "format=jwt_vc")
		assert.Contains(t, reason, "alg=ES384")
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

func TestMatchConstraints_Tracing(t *testing.T) {
	t.Run("logs rejection reason for non-matching credential", func(t *testing.T) {
		hook := captureTraceLogs(t, logrus.DebugLevel)
		pd := definitions().JSONLD
		matchingVC := vcrTest.ValidNutsOrganizationCredential(t)
		nonMatchingID := ssi.MustParseURI("urn:test:non-matching")
		nonMatchingVC := vc.VerifiableCredential{
			Type:              []ssi.URI{ssi.MustParseURI("VerifiableCredential")},
			ID:                &nonMatchingID,
			CredentialSubject: []map[string]any{{"id": "did:example:bob"}},
		}

		_, _, _ = pd.Match([]vc.VerifiableCredential{nonMatchingVC, matchingVC})

		msg := singleTraceMessage(t, hook)
		assert.Contains(t, msg, "PE: match evaluated")
		assert.Contains(t, msg, "input descriptor")
		assert.Contains(t, msg, "considered=2")
		assert.Contains(t, msg, "matched=1")
		assert.Contains(t, msg, "selected=")
		assert.Contains(t, msg, "rejected "+nonMatchingID.String())
		assert.Contains(t, msg, "no value found at any of paths")
	})

	t.Run("submission requirements satisfied and unsatisfied", func(t *testing.T) {
		hook := captureTraceLogs(t, logrus.DebugLevel)
		jsonldVC := vcrTest.ValidNutsOrganizationCredential(t)
		pd := PresentationDefinition{
			Id:               "sr-trace-test",
			InputDescriptors: twoGroupedInputDescriptors(),
			SubmissionRequirements: []*SubmissionRequirement{
				{Name: "Group A required", Rule: "all", From: "A"},
				{Name: "Group B (pick at least 1)", Rule: "pick", From: "B", Min: to.Ptr(1)},
			},
		}

		_, _, _ = pd.Match([]vc.VerifiableCredential{jsonldVC})

		msg := singleTraceMessage(t, hook)
		assert.Contains(t, msg, `submission requirement "Group A required" rule=all from=A`)
		assert.Contains(t, msg, "available=1")
		assert.Contains(t, msg, ": satisfied")
		assert.Contains(t, msg, `submission requirement "Group B (pick at least 1)" rule=pick from=B min=1 available=0`)
		assert.Contains(t, msg, "not satisfied")
		assert.Contains(t, msg, "less matches (0) than minimal required (1)")
		// errors.Join newline must have been collapsed.
		assert.NotContains(t, msg, ": missing credentials\nsubmission")
	})

	t.Run("continues collecting SR traces past errors", func(t *testing.T) {
		// When debug logging is on, a failing submission requirement must not abort the trace
		// — later requirements should still be evaluated and logged so the developer sees the
		// full picture.
		hook := captureTraceLogs(t, logrus.DebugLevel)
		jsonldVC := vcrTest.ValidNutsOrganizationCredential(t)
		pd := PresentationDefinition{
			Id:               "sr-trace-continues",
			InputDescriptors: twoGroupedInputDescriptors(),
			// SR1 (B / pick min=1) fails — group B has zero matches.
			// SR2 (A / all) would succeed — group A has one match.
			SubmissionRequirements: []*SubmissionRequirement{
				{Name: "B fails first", Rule: "pick", From: "B", Min: to.Ptr(1)},
				{Name: "A would succeed", Rule: "all", From: "A"},
			},
		}

		_, _, _ = pd.Match([]vc.VerifiableCredential{jsonldVC})

		msg := singleTraceMessage(t, hook)
		assert.Contains(t, msg, `submission requirement "B fails first"`)
		assert.Contains(t, msg, "not satisfied")
		assert.Contains(t, msg, `submission requirement "A would succeed"`)
		assert.Contains(t, msg, ": satisfied")
	})

	t.Run("no trace log when debug is disabled", func(t *testing.T) {
		hook := captureTraceLogs(t, logrus.InfoLevel)
		matchingVC := vcrTest.ValidNutsOrganizationCredential(t)

		_, _, _ = definitions().JSONLD.Match([]vc.VerifiableCredential{matchingVC})

		for _, e := range hook.AllEntries() {
			assert.NotEqual(t, "PE: match evaluated", strings.SplitN(e.Message, "\n", 2)[0],
				"trace log line should not be emitted when debug logging is disabled")
		}
	})
}

// captureTraceLogs sets the package logger to the given level and attaches a hook for the
// duration of the test. The hook is returned for the test to inspect emitted entries.
func captureTraceLogs(t *testing.T, level logrus.Level) *logTest.Hook {
	t.Helper()
	logger := log.Logger().Logger
	original := logger.Level
	hook := logTest.NewLocal(logger)
	logger.SetLevel(level)
	t.Cleanup(func() {
		logger.SetLevel(original)
		hook.Reset()
	})
	return hook
}

// singleTraceMessage asserts exactly one "PE: match evaluated" debug log was emitted and returns
// its full message. Returns "" when the assertion fails so the caller's later assertions don't panic.
func singleTraceMessage(t *testing.T, hook *logTest.Hook) string {
	t.Helper()
	var msgs []string
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.DebugLevel && strings.HasPrefix(e.Message, "PE: match evaluated") {
			msgs = append(msgs, e.Message)
		}
	}
	if !assert.Len(t, msgs, 1, "expected exactly one consolidated trace log entry") {
		return ""
	}
	return msgs[0]
}

// twoGroupedInputDescriptors returns the InputDescriptors used by the SR-trace subtests:
// "needs_org" in group A (matches the JSON-LD organization fixture) and "needs_other" in
// group B (never matches anything in this package's fixtures).
func twoGroupedInputDescriptors() []*InputDescriptor {
	return []*InputDescriptor{
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
	}
}
