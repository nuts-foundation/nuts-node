package credential

import (
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func CreateTestDezi07IDToken(issuedAt time.Time, validUntil time.Time, key crypto.PrivateKey) ([]byte, error) {
	claims := map[string]any{
		jwt.JwtIDKey:      "test-jwt-id-07",
		jwt.ExpirationKey: validUntil.Unix(),
		jwt.NotBeforeKey:  issuedAt.Unix(),
		jwt.IssuerKey:     "abonnee.dezi.nl",
		"json_schema":     "https://www.dezi.nl/json_schemas/verklaring_v1.json",
		"loa_dezi":        "http://eidas.europa.eu/LoA/high",
		"verklaring_id":   "test-verklaring-id",
		// v0.7 format claims
		"dezi_nummer":    "123456789",
		"voorletters":    "A.B.",
		"voorvoegsel":    "van der",
		"achternaam":     "Zorgmedewerker",
		"abonnee_nummer": "87654321",
		"abonnee_naam":   "Zorgaanbieder",
		"rol_code":       "01.000",
		"rol_naam":       "Arts",
		"rol_code_bron":  "http://www.dezi.nl/rol_code_bron/big",
	}
	token := jwt.New()
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			return nil, err
		}
	}

	headers := jws.NewHeaders()
	for k, v := range map[string]any{
		"alg": "RS256",
		"kid": "1",
		"jku": "https://example.com/jwks.json",
	} {
		if err := headers.Set(k, v); err != nil {
			return nil, err
		}
	}
	return jwt.Sign(token, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(headers)))
}

func CreateTestDezi2024IDToken(issuedAt time.Time, validUntil time.Time, key crypto.PrivateKey) ([]byte, error) {
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

	headers := jws.NewHeaders()
	for k, v := range map[string]any{
		"alg": "RS256",
		"kid": "1",
		"jku": "https://example.com/jwks.json",
	} {
		if err := headers.Set(k, v); err != nil {
			return nil, err
		}
	}
	return jwt.Sign(token, jwt.WithKey(jwa.RS256, key, jws.WithProtectedHeaders(headers)))
}
