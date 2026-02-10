package credential

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
)

func CreateDeziIDTokenCredential(idTokenSerialized string) (*vc.VerifiableCredential, error) {
	idToken, err := jwt.Parse([]byte(idTokenSerialized), jwt.WithVerify(false), jwt.WithAcceptableSkew(time.Hour*24*365*10))
	if err != nil {
		return nil, fmt.Errorf("parsing id_token: %w", err)
	}
	relationsRaw, _ := idToken.Get("relations")
	relations, ok := relationsRaw.([]any)
	if !ok || len(relations) != 1 {
		return nil, fmt.Errorf("id_token 'relations' claim invalid or missing (expected array of objects with single item)")
	}
	relation, ok := relations[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("id_token 'relations' claim invalid or missing (expected array of objects with single item)")
	}
	roles, ok := relation["roles"].([]any)
	if !ok {
		return nil, fmt.Errorf("id_token 'relations[0].roles' claim invalid or missing (expected array of strings)")
	}
	orgURA, ok := relation["ura"].(string)
	if !ok || orgURA == "" {
		return nil, fmt.Errorf("id_token 'relations[0].ura' claim invalid or missing (expected non-empty string)")
	}
	getString := func(claim string) string {
		value, ok := idToken.Get(claim)
		if !ok {
			return ""
		}
		result, _ := value.(string)
		return result
	}
	userID := getString("Dezi_id")
	if userID == "" {
		return nil, fmt.Errorf("id_token missing 'Dezi_id' claim")
	}
	initials := getString("initials")
	if initials == "" {
		return nil, fmt.Errorf("id_token missing 'initials' claim")
	}
	surname := getString("surname")
	if surname == "" {
		return nil, fmt.Errorf("id_token missing 'surname' claim")
	}
	surnamePrefix := getString("surname_prefix")
	if surnamePrefix == "" {
		return nil, fmt.Errorf("id_token missing 'surname_prefix' claim")
	}

	credentialMap := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			// TODO: Create JSON-LD context?
		},
		"type":           []string{"VerifiableCredential", "DeziIDTokenCredential"},
		"issuanceDate":   idToken.NotBefore().Format(time.RFC3339Nano),
		"expirationDate": idToken.Expiration().Format(time.RFC3339Nano),
		"credentialSubject": map[string]any{
			"@type":      "DeziIDTokenSubject",
			"identifier": orgURA,
			"name":       relation["entity_name"],
			"employee": map[string]any{
				"@type":         "HealthcareWorker",
				"identifier":    userID,
				"initials":      initials,
				"surnamePrefix": surnamePrefix,
				"surname":       surname,
				"roles":         roles,
			},
		},
		"proof": map[string]any{
			"type": "DeziIDJWT",
			"jwt":  idTokenSerialized,
		},
	}
	data, _ := json.Marshal(credentialMap)
	return vc.ParseVerifiableCredential(string(data))
}
