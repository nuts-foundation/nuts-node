package testsuite

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
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
	{
		name: "NutsAuthorizationCredential with localParameters",
		file: "authcred_001.ldjson",
	},
	{
		name: "NutsAuthorizationCredential without localParameters",
		file: "authcred_002.ldjson",
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
				"https://nuts.nl/credentials/v1": "../../vcr/assets/assets/contexts/nuts-v1_0.ldjson",
				jsonld.W3cVcContext:              "../../vcr/assets/assets/contexts/w3c-credentials-v1.ldjson",
				jsonld.Jws2020Context:            "../../vcr/assets/assets/contexts/lds-jws2020-v1.ldjson",
			}, ld.NewDefaultDocumentLoader(nil)),
		},
		{
			version: "1.1",
			loader: jsonld.NewMappedDocumentLoader(map[string]string{
				"https://nuts.nl/credentials/v1": "../../vcr/assets/assets/contexts/nuts-v1_1.ldjson",
				jsonld.W3cVcContext:              "../../vcr/assets/assets/contexts/w3c-credentials-v1.ldjson",
				jsonld.Jws2020Context:            "../../vcr/assets/assets/contexts/lds-jws2020-v1.ldjson",
			}, ld.NewDefaultDocumentLoader(nil)),
		},
	}

	for _, ctx := range contexts {
		if ctx.version == "1.1" {
			continue
		}
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
					err = ldProof.Verify(document.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: ctx.loader}, key.Public())
					assert.NoError(t, err)
				})
			}
		})
	}
}

func TestNutsV10LocalParametersSignature(t *testing.T) {
	loader := jsonld.NewMappedDocumentLoader(map[string]string{
		"https://nuts.nl/credentials/v1": "../../vcr/assets/assets/contexts/nuts-v1_1.ldjson",
		jsonld.W3cVcContext:              "../../vcr/assets/assets/contexts/w3c-credentials-v1.ldjson",
		jsonld.Jws2020Context:            "../../vcr/assets/assets/contexts/lds-jws2020-v1.ldjson",
	}, ld.NewDefaultDocumentLoader(nil))

	data, err := os.ReadFile("fixtures/authcred_001.ldjson")
	require.NoError(t, err)
	key := readSigningKey(t)

	var document proof.SignedDocument
	err = json.Unmarshal(data, &document)
	require.NoError(t, err)

	// Verify signature without alteration
	ldProof := proof.LDProof{}
	err = document.UnmarshalProofValue(&ldProof)
	require.NoError(t, err)
	err = ldProof.Verify(document.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: loader}, key.Public())
	require.NoError(t, err)

	// Alter localParameters field, signature should change
	document["credentialSubject"].(map[string]interface{})["localParameters"].(map[string]interface{})["single"] = "altered-value"
	ld.PrintDocument("", document)
	err = ldProof.Verify(document.DocumentWithoutProof(), signature.JSONWebSignature2020{ContextLoader: loader}, key.Public())
	assert.Error(t, err)
}

// TestGenerateSignedFixtures is used to generate signed test fixtures of the unsigned test cases.
// It's only there as runnable unit test to assert it keeps working.
func TestGenerateSignedFixtures(t *testing.T) {
	const saveSigned = false

	jsonldManager := jsonld.NewTestJSONLDManager(t)
	jsonldManager.DocumentLoader()

	loader := jsonld.NewMappedDocumentLoader(map[string]string{
		"https://nuts.nl/credentials/v1": "../../vcr/assets/assets/contexts/nuts-v1_0.ldjson",
		jsonld.W3cVcContext:              "../../vcr/assets/assets/contexts/w3c-credentials-v1.ldjson",
		jsonld.Jws2020Context:            "../../vcr/assets/assets/contexts/lds-jws2020-v1.ldjson",
	}, ld.NewDefaultDocumentLoader(nil))

	privateKey := readSigningKey(t)

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
			}).Sign(tbs, signature.JSONWebSignature2020{ContextLoader: loader}, privateKey)
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

func readSigningKey(t *testing.T) crypto.Key {
	pkPEMBytes, err := os.ReadFile("private_key.pem")
	require.NoError(t, err)
	pkDerBytes, _ := pem.Decode(pkPEMBytes)
	privateKey, err := x509.ParseECPrivateKey(pkDerBytes.Bytes)
	require.NoError(t, err)
	return crypto.TestKey{
		PrivateKey: privateKey,
		Kid:        "key-id",
	}
}
