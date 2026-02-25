package credential

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
	x5t := sha1.Sum(keyPair.Leaf.Raw)
	claims := map[string]any{
		jwk.KeyIDKey:              base64.StdEncoding.EncodeToString(x5t[:]),
		jwk.X509CertThumbprintKey: base64.StdEncoding.EncodeToString(x5t[:]),
		jwk.AlgorithmKey:          "RS256",
		jwt.AudienceKey:           "006fbf34-a80b-4c81-b6e9-593600675fb2",
		jwt.ExpirationKey:         validUntil.Unix(),
		jwt.NotBeforeKey:          issuedAt.Unix(),
		jwt.IssuerKey:             "https://max.proeftuin.Dezi-online.rdobeheer.nl",
		"initials":                "B.B.",
		"surname":                 "Jansen",
		"surname_prefix":          "van der",
		"Dezi_id":                 "900000009",
		"json_schema":             "https://max.proeftuin.Dezi-online.rdobeheer.nl/json_schema.json",
		"loa_authn":               "http://eidas.europa.eu/LoA/high",
		"loa_Dezi":                "http://eidas.europa.eu/LoA/high",
		"x5c":                     []string{base64.StdEncoding.EncodeToString(keyPair.Leaf.Raw)},
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
	return jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
}
