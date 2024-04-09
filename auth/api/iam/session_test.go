package iam

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUserWallet_Key(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		keyAsJWK, err := jwk.FromRaw(pk)
		require.NoError(t, err)
		jwkAsJSON, _ := json.Marshal(keyAsJWK)
		wallet := UserWallet{
			JWK: jwkAsJSON,
		}
		key, err := wallet.Key()
		require.NoError(t, err)
		assert.Equal(t, keyAsJWK, key)
	})
}
