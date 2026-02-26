package credential

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func CreateTestDeziIDToken(issuedAt time.Time, validUntil time.Time) ([]byte, error) {
	keyPair, err := tls.LoadX509KeyPair("../../test/pki/certificate-and-key.pem", "../../test/pki/certificate-and-key.pem")
	if err != nil {
		return nil, err
	}
	key, err := jwk.FromRaw(keyPair.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Create public key for the JWK Set
	// Extract the public key from the certificate
	publicKey, err := jwk.FromRaw(keyPair.Leaf.PublicKey)
	if err != nil {
		return nil, err
	}

	// Set the key ID
	x5t := sha1.Sum(keyPair.Leaf.Raw)
	kid := base64.StdEncoding.EncodeToString(x5t[:])
	if err := publicKey.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := publicKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, err
	}

	// Create JWK Set with the public key
	keySet := jwk.NewSet()
	if err := keySet.AddKey(publicKey); err != nil {
		return nil, err
	}

	// Marshal the JWK Set to JSON
	jwksJSON, err := json.Marshal(keySet)
	if err != nil {
		return nil, err
	}

	claims := map[string]any{
		jwt.AudienceKey:   "006fbf34-a80b-4c81-b6e9-593600675fb2",
		jwt.ExpirationKey: validUntil.Unix(),
		jwt.NotBeforeKey:  issuedAt.Unix(),
		jwt.IssuerKey:     "https://max.proeftuin.Dezi-online.rdobeheer.nl",
		"initials":        "B.B.",
		"surname":         "Jansen",
		"surname_prefix":  "van der",
		"Dezi_id":         "900000009",
		"json_schema":     "https://max.proeftuin.Dezi-online.rdobeheer.nl/json_schema.json",
		"loa_authn":       "http://eidas.europa.eu/LoA/high",
		"loa_Dezi":        "http://eidas.europa.eu/LoA/high",
		"jwks":            json.RawMessage(jwksJSON),
		"relations": []map[string]interface{}{
			{
				"entity_name": "Zorgaanbieder",
				"roles":       []string{"01.041", "30.000", "01.010", "01.011"},
				"ura":         "87654321",
			},
		},
	}
	token := jwt.New()
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			return nil, err
		}
	}

	// Create headers with kid
	headers := jws.NewHeaders()
	if err := headers.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}

	// Sign with the key ID in the header
	return jwt.Sign(token, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(headers)))
}
