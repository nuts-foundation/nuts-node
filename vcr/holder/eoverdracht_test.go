/*
 * Copyright (C) 2024 Nuts community
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

package holder

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// Test_eOverdracht_reproduceIssue reproduces the issue where the system fails to create a presentation
// when credentials don't have a credentialSubject.id field
func Test_eOverdracht_reproduceIssue(t *testing.T) {

	// Load credentials from dump
	credentialDumpBytes, err := os.ReadFile("credential-dump.json")
	require.NoError(t, err, "failed to read credential-dump.json")

	var allCredentials []interface{}
	err = json.Unmarshal(credentialDumpBytes, &allCredentials)
	require.NoError(t, err, "failed to parse credential-dump.json")

	// Parse credentials
	var credentials []vc.VerifiableCredential
	for _, credInterface := range allCredentials {
		switch cred := credInterface.(type) {
		case string:
			// JWT credentials
			parsedVC, err := vc.ParseVerifiableCredential(cred)
			if err != nil {
				t.Fatalf("Failed to parse JWT credential: %v", err)
			}
			credentials = append(credentials, *parsedVC)
		case map[string]interface{}:
			// JSON-LD credentials
			credBytes, _ := json.Marshal(cred)
			parsedVC, err := vc.ParseVerifiableCredential(string(credBytes))
			if err != nil {
				t.Fatalf("Failed to parse JSON-LD credential: %v", err)
			}
			credentials = append(credentials, *parsedVC)
		}
	}

	t.Logf("Loaded %d credentials", len(credentials))

	// Since there are no Dezi credentials in the dump, let's add one for testing
	var deziIdToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFlNDY4MjlkLWM4ZTgtNDhhMC1iZDZhLTIxYjhhMDdiOGNiMiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vYWNjZXB0YXRpZS5hdXRoLmRlemkubmwvZGV6aS9qd2tzLmpzb24ifQ.eyJqc29uX3NjaGVtYSI6Imh0dHBzOi8vd3d3LmRlemkubmwvanNvbl9zY2hlbWFzL3YxL3ZlcmtsYXJpbmcuanNvbiIsImxvYV9kZXppIjoiaHR0cDovL2VpZGFzLmV1cm9wYS5ldS9Mb0EvaGlnaCIsImp0aSI6ImY0MTBiMjU1LTZiMDctNDE4Mi1hYzVjLWM0MWYwMmJkMzk5NSIsInZlcmtsYXJpbmdfaWQiOiIwZTk3MGZjYi01MzBjLTQ4MmUtYmEyOC00N2I0NjFkNGRjYjUiLCJkZXppX251bW1lciI6IjkwMDAyMjE1OSIsInZvb3JsZXR0ZXJzIjoiSi4iLCJ2b29ydm9lZ3NlbCI6bnVsbCwiYWNodGVybmFhbSI6IjkwMDE3MzYyIiwiYWJvbm5lZV9udW1tZXIiOiI5MDAwMDM4MCIsImFib25uZWVfbmFhbSI6IlTDqXN0IFpvcmdpbnN0ZWxsaW5nIDAxIiwicm9sX2NvZGUiOiI5Mi4wMDAiLCJyb2xfbmFhbSI6Ik1vbmRoeWdpw6tuaXN0Iiwicm9sX2NvZGVfYnJvbiI6Imh0dHA6Ly93d3cuZGV6aS5ubC9yb2xfYnJvbi9iaWciLCJzdGF0dXNfdXJpIjoiaHR0cHM6Ly9hY2NlcHRhdGllLmF1dGguZGV6aS5ubC9zdGF0dXMvdjEvdmVya2xhcmluZy8wZTk3MGZjYi01MzBjLTQ4MmUtYmEyOC00N2I0NjFkNGRjYjUiLCJuYmYiOjE3NzI2NjUyMDAsImV4cCI6MTc4MDYxMDQwMCwiaXNzIjoiaHR0cHM6Ly9hYm9ubmVlLmRlemkubmwifQ.ipR4stqmO8MOmmapukeQxIOVpwO_Ipjgy5BHjUsdCvuFObhVrj48AQCndtV48D_Ol1hXO4s9p4b-1epjEiobjEmEO0JQNU0BAOGG0eWl8MujfhzlDnmwo5AEtvdgTjlnBaLReVu1BJ8KYgc1DT7JhCukq9z5wZLqU1aqtETleX2-s-dNdTdwrUjJa1DvIgO-DQ_rCp-1tcfkr2rtyW16ztyI88Q2YdBkNGcG0if5aYZHpcQ4-121WBObUa0FhswS7EHni5Ru8KwZNq0HC8OLWw3YqLrYHTFe2K0GQjMtEO6zNxApbMXWKlgeWdf7Ry2rPpe2l9Z5NuMrFiB8JChZsQ"
	deziVC, err := credential.CreateDeziUserCredential(deziIdToken)
	require.NoError(t, err)

	// Load presentation definition
	policyBytes, err := os.ReadFile("eOverdracht-policy.json")
	require.NoError(t, err, "failed to read eOverdracht-policy.json")

	var policies map[string]map[string]pe.PresentationDefinition
	err = json.Unmarshal(policyBytes, &policies)
	require.NoError(t, err, "failed to parse eOverdracht-policy.json")

	presentationDefinition := policies["eOverdracht-sender"]["organization"]
	t.Logf("Loaded presentation definition: %s", presentationDefinition.Id)

	// Group credentials by holder DID
	// Credentials without credentialSubject.id (like Dezi credentials) should be treated as "additional credentials"
	credentialsByHolderRaw := make(map[did.DID][]vc.VerifiableCredential)

	for _, cred := range credentials {
		// Try to get the subject DID
		subjectDID, err := cred.SubjectDID()
		require.NoError(t, err)
		credentialsByHolderRaw[*subjectDID] = append(credentialsByHolderRaw[*subjectDID], cred)
	}

	t.Logf("Credentials grouped by %d holders (without API layer processing)", len(credentialsByHolderRaw))

	// Get wallet DIDs
	var deziCreds = map[did.DID][]vc.VerifiableCredential{}
	var walletDIDs []did.DID
	for walletDID := range credentialsByHolderRaw {
		walletDIDs = append(walletDIDs, walletDID)
		t.Logf("Wallet DID: %s", walletDID)
		deziCreds[walletDID] = []vc.VerifiableCredential{credential.AutoCorrectSelfAttestedCredential(*deziVC, walletDID)}
	}

	ctx := audit.TestContext()
	ctrl := gomock.NewController(t)

	// Setup test infrastructure
	jsonldManager := jsonld.NewTestJSONLDManager(t)
	keyStorage := crypto.NewMemoryStorage()
	keyStore := crypto.NewTestCryptoInstance(orm.NewTestDatabase(t), keyStorage)

	// Setup keys for wallet DIDs
	key := vdr.TestMethodDIDAPrivateKey()
	for _, walletDID := range walletDIDs {
		kid := walletDID.String() + "#key-1"
		_ = keyStorage.SavePrivateKey(ctx, kid, key.PrivateKey)
		_ = keyStore.Link(ctx, kid, kid, "1")
	}

	keyResolver := resolver.NewMockKeyResolver(ctrl)
	keyResolver.EXPECT().ResolveKey(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(id did.DID, validAt *time.Time, relationshipType resolver.RelationType) (string, interface{}, error) {
		kid := id.String() + "#key-1"
		return kid, key.PublicKey, nil
	}).AnyTimes()

	// Create MemoryWallet with regular credentials
	wallet := NewMemoryWallet(jsonldManager.DocumentLoader(), keyResolver, keyStore, credentialsByHolderRaw)

	params := BuildParams{
		Audience: "https://example.com",
		Nonce:    "test-nonce",
		Expires:  time.Now().Add(time.Hour),
		Format:   oauth.DefaultOpenIDSupportedFormats(),
	}

	_, _, err = wallet.BuildSubmission(ctx, walletDIDs, deziCreds, presentationDefinition, params)
	require.NoError(t, err)
}

// Test_DeziCredential_UnrecognizedProofType verifies that AutoCorrectSelfAttestedCredential
// correctly sets credentialSubject.id for DeziUserCredentials even with unrecognized proof types.
// This tests the fix for: https://github.com/nuts-foundation/nuts-node/issues/XXXX
func Test_DeziCredential_UnrecognizedProofType(t *testing.T) {
	// Create a mock Dezi credential with an UNRECOGNIZED proof type
	// This simulates what happens if Dezi updates their spec with a new proof type
	idURI := ssi.MustParseURI("f410b255-6b07-4182-ac5c-c41f02bd3995")
	expirationDate := time.Now().Add(time.Hour * 24 * 365)
	mockDeziCredential := vc.VerifiableCredential{
		Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
		Type: []ssi.URI{
			ssi.MustParseURI("VerifiableCredential"),
			credential.DeziUserCredentialTypeURI,
		},
		ID:            &idURI,
		Issuer:        ssi.MustParseURI("https://abonnee.dezi.nl"),
		IssuanceDate:  time.Now(),
		ExpirationDate: &expirationDate,
		CredentialSubject: []map[string]interface{}{
			{
				"@type": "DeziIDTokenSubject",
				"identifier": "90000380",
				// NOTE: No "id" field!
			},
		},
		Proof: []interface{}{
			map[string]interface{}{
				"type": "DeziIDJWT2025", // ← UNRECOGNIZED proof type (not in DeziIDJWTProofTypes())
				"jwt":  "eyJhbGc...",
			},
		},
	}

	// Verify it has NO credentialSubject.id initially
	_, err := mockDeziCredential.SubjectDID()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no ID")
	t.Logf("✓ Confirmed: Dezi credential has NO credentialSubject.id before correction")

	// Apply AutoCorrectSelfAttestedCredential
	walletDID := did.MustParseDID("did:web:example.com:wallet")
	correctedVC := credential.AutoCorrectSelfAttestedCredential(mockDeziCredential, walletDID)

	// Verify it NOW HAS credentialSubject.id set to the wallet DID
	subjectDID, err := correctedVC.SubjectDID()
	require.NoError(t, err, "AutoCorrectSelfAttestedCredential should set credentialSubject.id for DeziUserCredential regardless of proof type")
	assert.Equal(t, walletDID.String(), subjectDID.String())
	t.Logf("✓ SUCCESS: AutoCorrectSelfAttestedCredential correctly set credentialSubject.id=%s", subjectDID)
	t.Logf("  Even though proof type 'DeziIDJWT2025' is not in DeziIDJWTProofTypes(): %v", credential.DeziIDJWTProofTypes())
	t.Logf("  This is because the credential has type=DeziUserCredential, which triggers correction")
}
