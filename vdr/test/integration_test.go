package test

import (
	crypt "crypto"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerificationMethodTypes(t *testing.T) {
	keyStore := crypto.NewMemoryCryptoInstance()
	networkInstance := network.NewTestNetworkInstance(t)
	storageEngine := storage.NewTestStorageEngine(t)
	module := vdr.NewVDR(keyStore, networkInstance, nil, nil, storageEngine)
	cfg := core.NewServerConfig()
	cfg.URL = "https://example.com"
	err := module.Configure(*cfg)
	require.NoError(t, err)

	type testCase struct {
		name                           string
		VerificationMethodType         ssi.KeyType
		ExpectedVerificationMethodType ssi.KeyType
	}
	testCases := []testCase{
		{
			name:                           "default",
			ExpectedVerificationMethodType: ssi.JsonWebKey2020,
		},
		{
			name:                   "JsonWebKey2020",
			VerificationMethodType: ssi.JsonWebKey2020,
		},
		{
			name:                   "EcdsaSecp256k1VerificationKey2019",
			VerificationMethodType: ssi.ECDSASECP256K1VerificationKey2019,
		},
		{
			name:                   "Ed25519VerificationKey2018",
			VerificationMethodType: ssi.ED25519VerificationKey2018,
		},
		// go-did VerificationMethod.PublicKey() is missing support for RsaVerificationKey2018
		//{
		//	name:                   "RsaVerificationKey2018",
		//	VerificationMethodType: ssi.RSAVerificationKey2018,
		//},
	}

	ctx := audit.TestContext()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create DID document
			opts := management.DIDCreationOptions{VerificationMethodType: tc.VerificationMethodType}
			document, key, err := module.Create(ctx, didweb.MethodName, opts)
			require.NoError(t, err)
			require.NotNil(t, key)
			require.NotNil(t, document)

			// Assert right verification method is created
			expected := tc.ExpectedVerificationMethodType
			if expected == "" {
				expected = tc.VerificationMethodType
			}
			method := document.VerificationMethod[0]
			require.Equal(t, expected, method.Type)
			publicKey, err := method.PublicKey()
			require.NoError(t, err)
			require.NotNil(t, publicKey)

			// Sign and verify signature
			token, err := keyStore.SignJWT(ctx, nil, nil, key)
			require.NoError(t, err)
			parsedToken, err := crypto.ParseJWT(token, func(kid string) (crypt.PublicKey, error) {
				return publicKey, nil
			})
			require.NoError(t, err)
			require.NotNil(t, parsedToken)
		})
	}
}
