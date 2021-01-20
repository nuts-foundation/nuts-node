package vdr

import (
	"crypto"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

// mockKeyCreator can create new keys based on a predefined key
type mockKeyCreator struct {
	// jwkStr hold the predefined key in a json web key string
	jwkStr string
}

// New uses a predefined ECDSA key and calls the namingFunc to get the kid
func (m *mockKeyCreator) New(namingFunc nutsCrypto.KidNamingFunc) (crypto.PublicKey, string, error) {
	keySet, err := jwk.ParseString(m.jwkStr)
	if err != nil {
		return nil, "", err
	}
	key := keySet.Keys[0]

	var rawKey crypto.PublicKey
	if key.Raw(&rawKey) != nil {
		return nil, "", err
	}
	kid, err := namingFunc(rawKey)
	if err != nil {
		return nil, "", err
	}
	return rawKey, kid, nil
}

func TestDocCreator_Create(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		kc := &mockKeyCreator{
			`{"crv":"P-256","kid":"did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE","kty":"EC","x":"Qn6xbZtOYFoLO2qMEAczcau9uGGWwa1bT+7JmAVLtg4=","y":"d20dD0qlT+d1djVpAfrfsAfKOUxKwKkn1zqFSIuJ398="},"type":"JsonWebKey2020"}`,
		}
		sut := DocCreator{keyCreator: kc}
		t.Run("ok", func(t *testing.T) {
			doc, err := sut.Create()
			assert.NoError(t, err)
			assert.NotNil(t, doc)
			assert.Equal(t, "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS", doc.ID.String())
			assert.Len(t, doc.VerificationMethod, 1)
			assert.Equal(t, "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", doc.VerificationMethod[0].ID.String())
		})
	})
}
