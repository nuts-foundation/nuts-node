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

package testsuite

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
	"time"
)

type testCase struct {
	name string
	file string
}

var testCases = []testCase{
	// Note: there is no test for an NutsAuthorizationCredential with localParameters,
	// because localParameters in v1.1 aren't compatible with v1.0 since its type changed from @graph to @json.
	// This is not a problem, because nobody actually used it in v1.0.
	{
		name: "NutsAuthorizationCredential",
		file: "authcred_001.ldjson",
	},
	{
		name: "NutsOrganizationCredential",
		file: "orgcred_001.ldjson",
	},
}

// TestCompatibility tests backwards compatibility of the Nuts JSON-LD context.
// It uses the test cases found in ./fixtures and checks the signature against every Nuts JSON-LD context version.
func TestCompatibility(t *testing.T) {
	key := readSigningKey(t)
	type context struct {
		version string
		loader  ld.DocumentLoader
	}
	contexts := []context{
		{
			version: "1.0",
			loader: jsonld.NewMappedDocumentLoader(map[string]string{
				"https://nuts.nl/credentials/v1": "../../vcr/assets/assets/contexts/nuts.ldjson",
				jsonld.W3cVcContext:              "../../vcr/assets/assets/contexts/w3c-credentials-v1.ldjson",
				jsonld.Jws2020Context:            "../../vcr/assets/assets/contexts/lds-jws2020-v1.ldjson",
			}, ld.NewDefaultDocumentLoader(nil)),
		},
	}

	for _, ctx := range contexts {
		t.Run(ctx.version, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.file, func(t *testing.T) {
					data, err := os.ReadFile("./fixtures/" + tc.file)
					require.NoError(t, err)
					var document proof.SignedDocument
					err = json.Unmarshal(data, &document)
					require.NoError(t, err)

					ldProof := proof.LDProof{}
					err = document.UnmarshalProofValue(&ldProof)
					require.NoError(t, err)
					err = ldProof.Verify(document.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: ctx.loader}, key.PublicKey)
					assert.NoError(t, err)
				})
			}
		})
	}
}

// TestGenerateSignedFixtures is used to generate signed test fixtures of the unsigned test cases.
// It's only there as runnable unit test to assert it keeps working.
func TestGenerateSignedFixtures(t *testing.T) {
	const saveSigned = false

	loader := jsonld.NewMappedDocumentLoader(map[string]string{
		"https://nuts.nl/credentials/v1": "../../vcr/assets/assets/contexts/nuts.ldjson",
		jsonld.W3cVcContext:              "../../vcr/assets/assets/contexts/w3c-credentials-v1.ldjson",
		jsonld.Jws2020Context:            "../../vcr/assets/assets/contexts/lds-jws2020-v1.ldjson",
	}, ld.NewDefaultDocumentLoader(nil))

	privateKey := readSigningKey(t)
	cryptoStorage := crypto.NewMemoryStorage()
	_ = cryptoStorage.SavePrivateKey(audit.TestContext(), privateKey.KID, privateKey.PrivateKey)
	keyStore := crypto.NewTestCryptoInstance(orm.NewTestDatabase(t), cryptoStorage)
	_ = keyStore.Link(audit.TestContext(), privateKey.KID, privateKey.KID, "1")

	for _, testCase := range testCases {
		t.Run(testCase.file, func(t *testing.T) {
			unsignedFile := "./fixtures/" + strings.ReplaceAll(testCase.file, ".ldjson", "_unsigned.ldjson")
			data, err := os.ReadFile(unsignedFile)
			require.NoError(t, err)

			var tbs proof.Document
			err = json.Unmarshal(data, &tbs)
			require.NoError(t, err)

			signed, err := proof.NewLDProof(proof.ProofOptions{
				Created: time.Now(),
			}).Sign(audit.TestContext(), tbs, signature.JSONWebSignature2020{ContextLoader: loader, Signer: keyStore}, privateKey.KID)
			require.NoError(t, err)

			var targetFile = "./fixtures/" + testCase.file
			// If not saving, still save it (although to temp dir) to it keeps working
			if !saveSigned {
				tempFile, err := os.CreateTemp("", testCase.file)
				defer func() {
					_ = os.Remove(tempFile.Name())
				}()
				require.NoError(t, err)
				_ = tempFile.Close()
				targetFile = tempFile.Name()
			}
			signedBytes, err := json.MarshalIndent(signed, "", "  ")
			require.NoError(t, err)
			// Copy file mode from unsigned file
			fileInfo, err := os.Stat(unsignedFile)
			require.NoError(t, err)
			err = os.WriteFile(targetFile, signedBytes, fileInfo.Mode())
			require.NoError(t, err)
			println("Written to", targetFile)
		})
	}
}

func readSigningKey(t *testing.T) crypto.TestKey {
	pkPEMBytes, err := os.ReadFile("private_key.pem")
	require.NoError(t, err)
	pkDerBytes, _ := pem.Decode(pkPEMBytes)
	privateKey, err := x509.ParseECPrivateKey(pkDerBytes.Bytes)
	require.NoError(t, err)
	return crypto.TestKey{
		PrivateKey: privateKey,
		KID:        "key-id",
		PublicKey:  privateKey.Public(),
	}
}
