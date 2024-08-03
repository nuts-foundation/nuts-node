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

package azure

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_Keyvault_Name(t *testing.T) {
	actual := Keyvault{}.Name()
	assert.Equal(t, "azure-keyvault", actual)
}

func Test_Keyvault_NewPrivateKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		response := azkeys.CreateKeyResponse{
			KeyBundle: keyBundle(),
		}

		capturedParams := azkeys.CreateKeyParameters{}
		vaultClient.EXPECT().CreateKey(gomock.Any(), "did-web-example-com-0", gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ string, parameters azkeys.CreateKeyParameters, _ *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
				capturedParams = parameters
				return response, nil
			})

		store := Keyvault{client: vaultClient}
		privateKey, version, err := store.NewPrivateKey(context.Background(), "did-web-example-com-0")
		require.NoError(t, err)
		assert.NotNil(t, privateKey)
		assert.Equal(t, "b86c2e6ad9054f4abf69cc185b99aa60", version)
		assert.Equal(t, azkeys.KeyTypeEC, *capturedParams.Kty)
		assert.Equal(t, azkeys.CurveNameP256, *capturedParams.Curve)
		assert.True(t, *capturedParams.KeyAttributes.Enabled)
		assert.False(t, *capturedParams.KeyAttributes.Exportable)
	})
}

func Test_Keyvault_GetPrivateKey(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().GetKey(gomock.Any(), "did-web-example-com-0", "", gomock.Any()).
			Return(azkeys.GetKeyResponse{
				KeyBundle: keyBundle(),
			}, nil)

		store := Keyvault{client: vaultClient}
		privateKey, err := store.GetPrivateKey(context.Background(), "did-web-example-com-0", "")
		require.NoError(t, err)
		assert.NotNil(t, privateKey)
	})
	t.Run("not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().GetKey(gomock.Any(), "did-web-example-com-0", "", gomock.Any()).
			Return(azkeys.GetKeyResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound})

		store := Keyvault{client: vaultClient}
		_, err := store.GetPrivateKey(context.Background(), "did-web-example-com-0", "")
		assert.ErrorIs(t, err, spi.ErrNotFound)
	})
	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().GetKey(gomock.Any(), "did-web-example-com-0", "", gomock.Any()).
			Return(azkeys.GetKeyResponse{}, errors.New("error"))

		store := Keyvault{client: vaultClient}
		_, err := store.GetPrivateKey(context.Background(), "did-web-example-com-0", "")
		assert.Error(t, err)
	})
	t.Run("unsupported key type", func(t *testing.T) {
		// Generate an RSA key to return
		privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
		privateKeyAsJWK, err := jwk.FromRaw(privateKey.PublicKey)
		require.NoError(t, err)
		privateKeyJWKAsBytes_, _ := json.Marshal(privateKeyAsJWK)
		var jsonWebKey azkeys.JSONWebKey
		err = json.Unmarshal(privateKeyJWKAsBytes_, &jsonWebKey)
		require.NoError(t, err)

		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().GetKey(gomock.Any(), "did-web-example-com-0", "", gomock.Any()).
			Return(azkeys.GetKeyResponse{
				KeyBundle: azkeys.KeyBundle{
					Key: &jsonWebKey,
				},
			}, nil)

		store := Keyvault{client: vaultClient}
		_, err = store.GetPrivateKey(context.Background(), "did-web-example-com-0", "")
		assert.EqualError(t, err, "only ES256 keys are supported")
	})
}

func Test_Keyvault_PrivateKeyExists(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().GetKey(gomock.Any(), "did-web-example-com-0", "", gomock.Any()).
			Return(azkeys.GetKeyResponse{
				KeyBundle: keyBundle(),
			}, nil)

		store := Keyvault{client: vaultClient}
		exists, err := store.PrivateKeyExists(context.Background(), "did-web-example-com-0", "")
		require.NoError(t, err)
		assert.True(t, exists)
	})
	t.Run("not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().GetKey(gomock.Any(), "did-web-example-com-0", "", gomock.Any()).
			Return(azkeys.GetKeyResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound})

		store := Keyvault{client: vaultClient}
		exists, err := store.PrivateKeyExists(context.Background(), "did-web-example-com-0", "")
		require.NoError(t, err)
		assert.False(t, exists)
	})
	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().GetKey(gomock.Any(), "did-web-example-com-0", "", gomock.Any()).
			Return(azkeys.GetKeyResponse{}, errors.New("error"))

		store := Keyvault{client: vaultClient}
		exists, err := store.PrivateKeyExists(context.Background(), "did-web-example-com-0", "")
		assert.Error(t, err)
		assert.False(t, exists)
	})
}

func Test_Keyvault_DeletePrivateKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().DeleteKey(gomock.Any(), "did-web-example-com-0", gomock.Any()).
			Return(azkeys.DeleteKeyResponse{}, nil)

		store := Keyvault{client: vaultClient}
		err := store.DeletePrivateKey(context.Background(), "did-web-example-com-0")
		require.NoError(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().DeleteKey(gomock.Any(), "did-web-example-com-0", gomock.Any()).
			Return(azkeys.DeleteKeyResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound})

		store := Keyvault{client: vaultClient}
		err := store.DeletePrivateKey(context.Background(), "did-web-example-com-0")
		assert.ErrorIs(t, err, spi.ErrNotFound)
	})
	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		vaultClient.EXPECT().DeleteKey(gomock.Any(), "did-web-example-com-0", gomock.Any()).
			Return(azkeys.DeleteKeyResponse{}, errors.New("error"))

		store := Keyvault{client: vaultClient}
		err := store.DeletePrivateKey(context.Background(), "did-web-example-com-0")
		assert.Error(t, err)
	})
}

func Test_azureSigningKey_Sign(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		// These constants are used to verify the ASN.1 marshalling of the signature (raw r|s to ASN.1)
		const signatureBase64Raw = "5jMTEt440Rtgx6NwtTOQA0m2gGo8mdGMwgbFyxB2vwGwjXhUNnxTRAlsVBDVV+BgUyARY9RU9aR1AoxoyXKKhg=="
		const signatureBase64ASN1 = "MEYCIQDmMxMS3jjRG2DHo3C1M5ADSbaAajyZ0YzCBsXLEHa/AQIhALCNeFQ2fFNECWxUENVX4GBTIBFj1FT1pHUCjGjJcoqG"

		ctrl := gomock.NewController(t)
		vaultClient := NewMockkeyVaultClient(ctrl)
		digest := sha256.Sum256([]byte("hello"))
		capturedParams := azkeys.SignParameters{}
		vaultClient.EXPECT().Sign(gomock.Any(), "sign", "", gomock.Any(), nil).
			DoAndReturn(func(_, _, _ interface{}, params azkeys.SignParameters, _ interface{}) (azkeys.SignResponse, error) {
				capturedParams = params
				data, _ := base64.StdEncoding.DecodeString(signatureBase64Raw)
				return azkeys.SignResponse{
					KeyOperationResult: azkeys.KeyOperationResult{Result: data},
				}, nil
			},
			)
		signature, err := azureSigningKey{
			client:           vaultClient,
			timeOut:          time.Second * 10,
			keyName:          "sign",
			signingAlgorithm: azkeys.SignatureAlgorithmES256,
		}.Sign(nil, digest[:], nil)
		require.NoError(t, err)

		assert.Equal(t, signatureBase64ASN1, base64.StdEncoding.EncodeToString(signature))
		assert.Equal(t, digest[:], capturedParams.Value)
		assert.Equal(t, azkeys.SignatureAlgorithmES256, *capturedParams.Algorithm)
	})
}

func keyBundle() azkeys.KeyBundle {
	id := azkeys.ID("https://myvaultname.vault.azure.net/keys/did-web-example-com-0/b86c2e6ad9054f4abf69cc185b99aa60")
	return azkeys.KeyBundle{
		Key: &azkeys.JSONWebKey{
			Kty: to.Ptr(azkeys.KeyTypeEC),
			Crv: to.Ptr(azkeys.CurveNameP256),
			X:   []byte{1, 2, 3},
			Y:   []byte{4, 5, 6},
			KID: &id,
		},
	}
}

// TestIntegrationTest tests the integration of the Azure Key Vault storage with a real Azure Key Vault.
func TestIntegrationTest(t *testing.T) {
	// Either set credential environment variables (e.g., AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET) or use az login
	t.Skip()
	os.Setenv("AZURE_TENANT_ID", "")
	os.Setenv("AZURE_CLIENT_ID", "")
	os.Setenv("AZURE_CLIENT_SECRET", "")

	store, err := New(Config{
		URL:     "https://geheim-Keyvault.vault.azure.net/",
		Timeout: 10 * time.Second,
		Auth:    AuthConfig{Type: DefaultChainCredentialType},
	})
	assert.NoError(t, err)

	var keyName = uuid.NewString()
	ctx := context.Background()
	_, version, err := store.NewPrivateKey(ctx, keyName)
	if !errors.Is(err, spi.ErrKeyAlreadyExists) {
		assert.NoError(t, err)
	}

	t.Run("New", func(t *testing.T) {
		t.Run("already exists", func(t *testing.T) {
			_, _, err := store.NewPrivateKey(ctx, keyName)
			assert.ErrorIs(t, err, spi.ErrKeyAlreadyExists)
		})
	})
	t.Run("PrivateKeyExists", func(t *testing.T) {
		t.Run("does not exist", func(t *testing.T) {
			exists, err := store.PrivateKeyExists(ctx, "does-not-exist", "")
			assert.NoError(t, err)
			assert.False(t, exists)
		})
		t.Run("exists", func(t *testing.T) {
			exists, err := store.PrivateKeyExists(ctx, keyName, version)
			assert.NoError(t, err)
			assert.True(t, exists)
		})
	})
	t.Run("ListPrivateKeys", func(t *testing.T) {
		keys := store.ListPrivateKeys(ctx)
		assert.Contains(t, keys, spi.KeyNameVersion{keyName, version})
	})
	t.Run("GetPrivateKey", func(t *testing.T) {
		t.Run("does not exist", func(t *testing.T) {
			_, err := store.GetPrivateKey(ctx, "does-not-exist", "")
			assert.ErrorIs(t, err, spi.ErrNotFound)
		})
		t.Run("sign", func(t *testing.T) {
			signer, err := store.GetPrivateKey(ctx, keyName, version)
			assert.NoError(t, err)

			// Sign something
			digest := sha256.Sum256([]byte("hello"))
			signature, err := signer.Sign(nil, digest[:], nil)
			assert.NoError(t, err)
			assert.NotNil(t, signature)
			// Verify the signature
			publicKey := signer.Public()
			valid := ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), digest[:], signature)
			assert.True(t, valid)
		})
	})
	t.Run("DeletePrivateKey", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			otherKeyName := uuid.NewString()
			_, version, err := store.NewPrivateKey(ctx, otherKeyName)
			assert.NoError(t, err)

			err = store.DeletePrivateKey(ctx, otherKeyName)
			assert.NoError(t, err)

			exists, err := store.PrivateKeyExists(ctx, otherKeyName, version)
			assert.NoError(t, err)
			assert.False(t, exists)
		})
		t.Run("does not exist", func(t *testing.T) {
			err := store.DeletePrivateKey(ctx, "does-not-exist")
			assert.ErrorIs(t, err, spi.ErrNotFound)
		})
	})
}
