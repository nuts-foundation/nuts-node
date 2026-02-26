package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
)

func CreateDeziIDTokenCredential(idTokenSerialized string) (*vc.VerifiableCredential, error) {
	// Parse without signature or time validation - those are validated elsewhere
	idToken, err := jwt.Parse([]byte(idTokenSerialized), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("parsing id_token: %w", err)
	}

	getString := func(claim string) string {
		value, ok := idToken.Get(claim)
		if !ok {
			return ""
		}
		result, _ := value.(string)
		return result
	}

	// Check if this is v0.7 format (has abonnee_nummer) or old format (has relations)
	isV07 := getString("abonnee_nummer") != ""

	var orgURA, orgName, userID, initials, surname, surnamePrefix string
	var roles []any

	if isV07 {
		// v0.7 spec format
		orgURA = getString("abonnee_nummer")
		if orgURA == "" {
			return nil, fmt.Errorf("id_token missing 'abonnee_nummer' claim")
		}
		orgName = getString("abonnee_naam")
		if orgName == "" {
			return nil, fmt.Errorf("id_token missing 'abonnee_naam' claim")
		}

		userID = getString("dezi_nummer")
		if userID == "" {
			return nil, fmt.Errorf("id_token missing 'dezi_nummer' claim")
		}
		initials = getString("voorletters")
		if initials == "" {
			return nil, fmt.Errorf("id_token missing 'voorletters' claim")
		}
		surname = getString("achternaam")
		if surname == "" {
			return nil, fmt.Errorf("id_token missing 'achternaam' claim")
		}
		surnamePrefix = getString("voorvoegsel") // Can be null/empty in v0.7

		// In v0.7, rol_code is a single string, not an array
		rolCode := getString("rol_code")
		if rolCode != "" {
			roles = []any{rolCode}
		}
	} else {
		// Old format with relations
		relationsRaw, _ := idToken.Get("relations")
		relations, ok := relationsRaw.([]any)
		if !ok || len(relations) != 1 {
			return nil, fmt.Errorf("id_token 'relations' claim invalid or missing (expected array of objects with single item)")
		}
		relation, ok := relations[0].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("id_token 'relations' claim invalid or missing (expected array of objects with single item)")
		}
		roles, ok = relation["roles"].([]any)
		if !ok {
			return nil, fmt.Errorf("id_token 'relations[0].roles' claim invalid or missing (expected array of strings)")
		}
		orgURA, ok = relation["ura"].(string)
		if !ok || orgURA == "" {
			return nil, fmt.Errorf("id_token 'relations[0].ura' claim invalid or missing (expected non-empty string)")
		}
		orgName, _ = relation["entity_name"].(string)

		userID = getString("Dezi_id")
		if userID == "" {
			return nil, fmt.Errorf("id_token missing 'Dezi_id' claim")
		}
		initials = getString("initials")
		if initials == "" {
			return nil, fmt.Errorf("id_token missing 'initials' claim")
		}
		surname = getString("surname")
		if surname == "" {
			return nil, fmt.Errorf("id_token missing 'surname' claim")
		}
		surnamePrefix = getString("surname_prefix")
		if surnamePrefix == "" {
			return nil, fmt.Errorf("id_token missing 'surname_prefix' claim")
		}
	}

	credentialMap := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			// TODO: Create JSON-LD context?
		},
		"type":           []string{"VerifiableCredential", "DeziIDTokenCredential"},
		"id":             idToken.JwtID(),
		"issuer":         idToken.Issuer(),
		"issuanceDate":   idToken.NotBefore().Format(time.RFC3339Nano),
		"expirationDate": idToken.Expiration().Format(time.RFC3339Nano),
		"credentialSubject": map[string]any{
			"@type":      "DeziIDTokenSubject",
			"identifier": orgURA,
			"name":       orgName,
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

// deziIDTokenCredentialValidator validates DeziIDTokenCredential, according to (TODO: add spec).
type deziIDTokenCredentialValidator struct {
	clock      func() time.Time
	httpClient *http.Client // Optional HTTP client for fetching JWK Set (for testing)
}

func (d deziIDTokenCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	type proofType struct {
		Type string `json:"type"`
		JWT  string `json:"jwt"`
	}
	proofs := []proofType{}
	if err := credential.UnmarshalProofValue(&proofs); err != nil {
		return fmt.Errorf("%w: invalid proof format: %w", errValidation, err)
	}
	if len(proofs) != 1 {
		return fmt.Errorf("%w: expected exactly one proof, got %d", errValidation, len(proofs))
	}
	proof := proofs[0]
	if proof.Type != "DeziIDJWT" {
		return fmt.Errorf("%w: invalid proof type: expected 'DeziIDJWT', got '%s'", errValidation, proof.Type)
	}
	if err := d.validateDeziToken(credential, proof.JWT); err != nil {
		return fmt.Errorf("%w: invalid Dezi id_token: %w", errValidation, err)
	}
	return (defaultCredentialValidator{}).Validate(credential)
}

func (d deziIDTokenCredentialValidator) validateDeziToken(credential vc.VerifiableCredential, serialized string) error {
	// Parse and verify the JWT
	// - WithVerifyAuto(nil, ...) uses default jwk.Fetch and automatically fetches the JWK Set from the jku header URL
	// - WithFetchWhitelist allows fetching from any https:// URL (Dezi endpoints)
	// - WithHTTPClient allows using a custom HTTP client (for testing with self-signed certs)
	// - WithValidate(false) skips exp/nbf validation since we validate those against credential dates
	fetchOptions := []jwk.FetchOption{jwk.WithFetchWhitelist(jwk.InsecureWhitelist{})}
	if d.httpClient != nil {
		fetchOptions = append(fetchOptions, jwk.WithHTTPClient(d.httpClient))
	}

	// TODO: Only allow specific domains for the jku
	// TODO: make sure it's signed with a jku
	token, err := jwt.Parse(
		[]byte(serialized),
		jwt.WithVerifyAuto(nil, fetchOptions...),
		jwt.WithValidate(false),
	)
	if err != nil {
		return fmt.Errorf("failed to verify JWT signature: %w", err)
	}

	// Validate that token timestamps match credential dates
	if !token.NotBefore().Equal(credential.IssuanceDate) {
		return errors.New("'nbf' does not match credential 'issuanceDate'")
	}
	if !token.Expiration().Equal(*credential.ExpirationDate) {
		return errors.New("'exp' does not match credential 'expirationDate'")
	}
	// TODO: implement rest of checks (claims)
	return nil
}
