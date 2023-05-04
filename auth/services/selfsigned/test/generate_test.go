package test

import (
	"context"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func Test_GenerateTestData(t *testing.T) {
	store := true

	contextLoader, _ := jsonld.NewContextLoader(false, jsonld.DefaultContextConfig())

	createdTime := time.Date(2023, 4, 20, 9, 53, 3, 0, time.UTC)
	expirationTime := createdTime.Add(4 * 24 * time.Hour)

	// Set up crypto
	const keyID = "did:nuts:8NYzfsndZJHh6GqzKiSBpyERrFxuX64z6tE5raa7nEjm#bYcuet6EHojMlaMqwNoC3c6etKlUHoJ9rRvUu3ZKEEw"
	privateKeyData, err := os.ReadFile("private.pem")
	require.NoError(t, err)
	privateKey, err := util.PemToPrivateKey(privateKeyData)
	require.NoError(t, err)
	key := crypto.TestKey{
		PrivateKey: privateKey,
		Kid:        keyID,
	}
	cryptoStorage := crypto.NewMemoryStorage()
	cryptoInstance := crypto.NewTestCryptoInstance(cryptoStorage)
	err = cryptoStorage.SavePrivateKey(context.Background(), keyID, key)
	require.NoError(t, err)

	jws2020 := signature.JSONWebSignature2020{ContextLoader: contextLoader, Signer: cryptoInstance}

	println("Generating vc.json...")
	var signedVC interface{}
	{
		data, err := os.ReadFile("vc.json")
		require.NoError(t, err)
		document := map[string]interface{}{}
		err = json.Unmarshal(data, &document)
		require.NoError(t, err)
		delete(document, "proof")

		pOptions := proof.ProofOptions{
			Created:      createdTime,
			Expires:      &expirationTime,
			ProofPurpose: "assertionMethod",
		}
		ldProof := proof.NewLDProof(pOptions)

		signedVC, err = ldProof.Sign(audit.TestContext(), document, jws2020, key)
		require.NoError(t, err)
		data, err = json.MarshalIndent(signedVC, "", "  ")
		require.NoError(t, err)
		stat, _ := os.Stat("vc.json")
		if store {
			err = os.WriteFile("vc.json", data, stat.Mode())
			require.NoError(t, err)
		}
	}

	println("Generating vp.json...")
	{
		data, err := os.ReadFile("vp.json")
		require.NoError(t, err)
		document := map[string]interface{}{}
		err = json.Unmarshal(data, &document)
		require.NoError(t, err)
		delete(document, "proof")
		document["verifiableCredential"] = []interface{}{signedVC}

		challenge := "EN:PractitionerLogin:v3 I hereby declare to act on behalf of CareBears located in Caretown. This declaration is valid from Wednesday, 19 April 2023 12:20:00 until Thursday, 20 April 2023 13:20:00."
		pOptions := proof.ProofOptions{
			Challenge:    &challenge,
			Created:      createdTime,
			Expires:      &expirationTime,
			ProofPurpose: "assertionMethod",
		}
		ldProof := proof.NewLDProof(pOptions)

		result, err := ldProof.Sign(audit.TestContext(), document, jws2020, key)
		require.NoError(t, err)
		data, err = json.MarshalIndent(result, "", "  ")
		require.NoError(t, err)
		stat, _ := os.Stat("vp.json")
		if store {
			err = os.WriteFile("vp.json", data, stat.Mode())
			require.NoError(t, err)
		}
	}
}
