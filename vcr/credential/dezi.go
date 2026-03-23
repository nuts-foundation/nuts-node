package credential

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
)

type DeziIDTokenSubject struct {
	Identifier string           `json:"identifier"`
	Name       string           `json:"name,omitempty"`
	Employee   HealthcareWorker `json:"employee"`
}

func (d DeziIDTokenSubject) MarshalJSON() ([]byte, error) {
	type Alias DeziIDTokenSubject
	aux := struct {
		Alias
		Type string `json:"@type"`
	}{
		Alias: Alias(d),
		Type:  "DeziIDTokenSubject",
	}
	return json.Marshal(aux)
}

type HealthcareWorker struct {
	Identifier    string `json:"identifier"`
	Initials      string `json:"initials"`
	SurnamePrefix string `json:"surnamePrefix"`
	Surname       string `json:"surname"`
	Role          string `json:"role,omitempty"`
	RoleRegistry  string `json:"role_registry,omitempty"`
	RoleName      string `json:"role_name,omitempty"`
}

func (d HealthcareWorker) MarshalJSON() ([]byte, error) {
	type Alias HealthcareWorker
	aux := struct {
		Alias
		Type string `json:"@type"`
	}{
		Alias: Alias(d),
		Type:  "HealthcareWorker",
	}
	return json.Marshal(aux)
}

// CreateDeziUserCredential creates a Verifiable Credential from a Dezi id_token JWT. It supports the following spec versions:
// - april 2024
// - 15 jan 2026/v0.7: https://www.dezi.nl/documenten/2024/04/24/koppelvlakspecificatie-dezi-voor-platform--en-softwareleveranciers
func CreateDeziUserCredential(idTokenSerialized string) (*vc.VerifiableCredential, error) {
	// Parse without signature or time validation - those are validated elsewhere
	idToken, err := jwt.Parse([]byte(idTokenSerialized), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("parsing id_token: %w", err)
	}

	subject, version, err := extractDeziIDTokenSubject(idToken)
	if err != nil {
		return nil, err
	}

	// Determine proof type based on version
	var proofTypeName string
	switch version {
	case "2024":
		proofTypeName = "DeziIDJWT2024"
	case "0.7":
		proofTypeName = "DeziIDJWT07"
	default:
		return nil, fmt.Errorf("unsupported Dezi id_token version: %s", version)
	}

	credentialMap := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			// TODO: Create JSON-LD context?
		},
		"type":              []string{"VerifiableCredential", "DeziUserCredential"},
		"id":                idToken.JwtID(),
		"issuer":            idToken.Issuer(),
		"issuanceDate":      idToken.NotBefore().Format(time.RFC3339Nano),
		"expirationDate":    idToken.Expiration().Format(time.RFC3339Nano),
		"credentialSubject": subject,
		"proof": deziProofType{
			Type: proofTypeName,
			JWT:  idTokenSerialized,
		},
	}
	data, _ := json.Marshal(credentialMap)
	return vc.ParseVerifiableCredential(string(data))
}

var _ Validator = DeziUserCredentialValidator{}

type DeziUserCredentialValidator struct {
	trustStore *core.TrustStore
	// AllowedJKU is a list of allowed jku URLs for fetching JWK Sets (for v0.7 tokens), used to verify Dezi attestations.
	AllowedJKU []string
}

func (d DeziUserCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	_, version, err := parseDeziProofType(credential)
	if err != nil {
		return err
	}
	switch version {
	case "2024":
		return deziIDToken2024CredentialValidator{
			clock:      time.Now,
			trustStore: d.trustStore,
		}.Validate(credential)
	case "0.7":
		return deziIDToken07CredentialValidator{
			clock:      time.Now,
			allowedJKU: d.AllowedJKU,
		}.Validate(credential)
	default:
		return fmt.Errorf("%w: unsupported Dezi id_token version: %s", errValidation, version)
	}
}

var _ Validator = deziIDToken2024CredentialValidator{}

// deziIDToken2024CredentialValidator validates DeziIDTokenCredential,
// according to spec of april 2024 (uses x5c in JWT payload instead of jku header)
type deziIDToken2024CredentialValidator struct {
	clock      func() time.Time
	trustStore *core.TrustStore
}

func (d deziIDToken2024CredentialValidator) Validate(credential vc.VerifiableCredential) error {
	proof, _, err := parseDeziProofType(credential)
	if err != nil {
		return fmt.Errorf("%w: %w", errValidation, err)
	}

	idToken, err := d.validateIDToken(credential, proof.JWT)
	if err != nil {
		return fmt.Errorf("%w: invalid Dezi id_token: %w", errValidation, err)
	}

	// Validate that token timestamps match credential dates
	if !idToken.NotBefore().Equal(credential.IssuanceDate) {
		return errors.New("id_token 'nbf' does not match credential 'issuanceDate'")
	}
	if !idToken.Expiration().Equal(*credential.ExpirationDate) {
		return errors.New("id_token 'exp' does not match credential 'expirationDate'")
	}

	// Validate that the

	return (defaultCredentialValidator{}).Validate(credential)
}

func (d deziIDToken2024CredentialValidator) validateIDToken(credential vc.VerifiableCredential, serialized string) (jwt.Token, error) {
	// Parse without verification first to extract x5c from payload
	token, err := jwt.Parse([]byte(serialized), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	// After signature has been validated, token can be considered a valid JWT
	err = d.validateSignature(token, err, serialized)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return token, nil
}

func (d deziIDToken2024CredentialValidator) validateSignature(token jwt.Token, err error, serialized string) error {
	// Extract x5c claim from payload (not header - this is non-standard but per 2024 spec)
	x5cRaw, ok := token.Get("x5c")
	if !ok {
		return errors.New("missing 'x5c' claim in JWT payload")
	}

	var x5c []any
	switch v := x5cRaw.(type) {
	case []any:
		x5c = v
	case string:
		x5c = []any{v}
	default:
		return errors.New("'x5c' claim must be either a string or an array of strings")
	}

	// Parse the certificate chain
	var certChain [][]byte
	for i, certData := range x5c {
		certStr, ok := certData.(string)
		if !ok {
			return fmt.Errorf("'x5c[%d]' must be a string", i)
		}
		// x5c contains base64-encoded DER certificates
		certBytes, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return fmt.Errorf("decode 'x5c[%d]': %w", i, err)
		}
		certChain = append(certChain, certBytes)
	}

	if len(certChain) == 0 {
		return errors.New("'x5c' certificate chain is empty")
	}

	// Parse the leaf certificate (first in chain)
	leafCert, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return fmt.Errorf("parse signing certificate: %w", err)
	}

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         core.NewCertPool(d.trustStore.RootCAs),
		CurrentTime:   d.clock(),
		Intermediates: core.NewCertPool(d.trustStore.IntermediateCAs),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // TODO: use more specific key usage if possible
	})
	if err != nil {
		return fmt.Errorf("verify Dezi certificate chain: %w", err)
	}

	// Verify the JWT signature using the leaf certificate's public key
	_, err = jwt.Parse([]byte(serialized), jwt.WithKey(jwa.RS256, leafCert.PublicKey), jwt.WithValidate(true), jwt.WithClock(jwt.ClockFunc(d.clock)))
	if err != nil {
		return err
	}
	return nil
}

// deziIDToken07CredentialValidator validates DeziUserCredential,
// according to v0.7 spec of 15-01-2026 (https://www.dezi.nl/documenten/2025/12/15/koppelvlakspecificatie-dezi-voor-platform--en-softwareleveranciers)
type deziIDToken07CredentialValidator struct {
	clock      func() time.Time
	httpClient *http.Client // Optional HTTP client for fetching JWK Set (for testing)
	allowedJKU []string     // List of allowed jku URLs
}

func (d deziIDToken07CredentialValidator) Validate(credential vc.VerifiableCredential) error {
	proof, _, err := parseDeziProofType(credential)
	if err != nil {
		return fmt.Errorf("%w: %w", errValidation, err)
	}
	if err := d.validateDeziToken(credential, proof.JWT); err != nil {
		return fmt.Errorf("%w: invalid Dezi id_token: %w", errValidation, err)
	}
	return (defaultCredentialValidator{}).Validate(credential)
}

func (d deziIDToken07CredentialValidator) validateDeziToken(credential vc.VerifiableCredential, serialized string) error {
	// Parse and verify the JWT
	// - WithVerifyAuto(nil, ...) uses default jwk.Fetch and automatically fetches the JWK Set from the jku header URL
	// - WithFetchWhitelist allows fetching from any https:// URL (Dezi endpoints)
	// - WithHTTPClient allows using a custom HTTP client (for testing with self-signed certs)
	fetchOptions := []jwk.FetchOption{jwk.WithFetchWhitelist(jwk.WhitelistFunc(func(requestedURL string) bool {
		return slices.Contains(d.allowedJKU, requestedURL)
	}))}
	if d.httpClient != nil {
		fetchOptions = append(fetchOptions, jwk.WithHTTPClient(d.httpClient))
	}

	// TODO: Only allow specific domains for the jku
	// TODO: make sure it's signed with a jku
	token, err := jwt.Parse(
		[]byte(serialized),
		jwt.WithVerifyAuto(nil, fetchOptions...),
		jwt.WithClock(jwt.ClockFunc(d.clock)),
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

	var credentialSubject []DeziIDTokenSubject
	if err = credential.UnmarshalCredentialSubject(&credentialSubject); err != nil {
		return fmt.Errorf("invalid credential subject format: %w", err)
	}
	if len(credentialSubject) != 1 {
		return fmt.Errorf("expected exactly one credential subject, got %d", len(credentialSubject))
	}

	subjectFromToken, _, err := extractDeziIDTokenSubject(token)
	if err != nil {
		return fmt.Errorf("invalid id_token claims: %w", err)
	}
	if !reflect.DeepEqual(credentialSubject[0], subjectFromToken) {
		return errors.New("credential subject does not match id_token claims")
	}

	// TODO: check id_token revocation
	return nil
}

type deziProofType struct {
	Type string `json:"type"`
	JWT  string `json:"jwt"`
}

func parseDeziProofType(credential vc.VerifiableCredential) (*deziProofType, string, error) {
	var proofs []deziProofType
	if err := credential.UnmarshalProofValue(&proofs); err != nil {
		return nil, "", fmt.Errorf("invalid proof format: %w", err)
	}
	if len(proofs) != 1 {
		return nil, "", fmt.Errorf("expected exactly one proof, got %d", len(proofs))
	}
	proof := &proofs[0]

	// Derive version from proof type
	var version string
	switch proof.Type {
	case "DeziIDJWT2024":
		version = "2024"
	case "DeziIDJWT07":
		version = "0.7"
	default:
		return nil, "", fmt.Errorf("invalid proof type: expected 'DeziIDJWT2024' or 'DeziIDJWT07', got '%s'", proof.Type)
	}

	return proof, version, nil
}

// extractDeziIDTokenSubject extracts and validates the subject information from a Dezi id_token JWT.
// It returns the DeziIDTokenSubject, the detected version ("2024" or "0.7"), and any error encountered.
func extractDeziIDTokenSubject(idToken jwt.Token) (DeziIDTokenSubject, string, error) {
	// Check if this is v0.7 format (has abonnee_nummer) or 2024 format (has relations)
	var version string
	{
		_, hasRelations := idToken.Get("relations")
		if hasRelations {
			version = "2024"
		} else {
			version = "0.7"
		}
	}

	switch version {
	case "0.7":
		return extractDezi07Subject(idToken)
	case "2024":
		return extractDezi2024Subject(idToken)
	default:
		return DeziIDTokenSubject{}, "", fmt.Errorf("unsupported Dezi id_token version: %s", version)
	}
}

// extractDezi07Subject extracts the subject from a v0.7 Dezi id_token
func extractDezi07Subject(idToken jwt.Token) (DeziIDTokenSubject, string, error) {
	getString := func(claim string) string {
		value, ok := idToken.Get(claim)
		if !ok {
			return ""
		}
		result, _ := value.(string)
		return result
	}

	orgURA := getString("abonnee_nummer")
	if orgURA == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'abonnee_nummer' claim")
	}
	orgName := getString("abonnee_naam")
	if orgName == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'abonnee_naam' claim")
	}

	userID := getString("dezi_nummer")
	if userID == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'dezi_nummer' claim")
	}
	initials := getString("voorletters")
	if initials == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'voorletters' claim")
	}
	surname := getString("achternaam")
	if surname == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'achternaam' claim")
	}
	surnamePrefix := getString("voorvoegsel") // Can be null/empty in v0.7

	role := getString("rol_code")
	roleRegistry := getString("rol_code_bron")
	roleName := getString("rol_naam")

	return DeziIDTokenSubject{
		Identifier: orgURA,
		Name:       orgName,
		Employee: HealthcareWorker{
			Identifier:    userID,
			Initials:      initials,
			SurnamePrefix: surnamePrefix,
			Surname:       surname,
			Role:          role,
			RoleRegistry:  roleRegistry,
			RoleName:      roleName,
		},
	}, "0.7", nil
}

// extractDezi2024Subject extracts the subject from a 2024 Dezi id_token
func extractDezi2024Subject(idToken jwt.Token) (DeziIDTokenSubject, string, error) {
	getString := func(claim string) string {
		value, ok := idToken.Get(claim)
		if !ok {
			return ""
		}
		result, _ := value.(string)
		return result
	}

	relationsRaw, _ := idToken.Get("relations")
	relations, ok := relationsRaw.([]any)
	if !ok || len(relations) != 1 {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token 'relations' claim invalid or missing (expected array of objects with single item)")
	}
	relation, ok := relations[0].(map[string]any)
	if !ok {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token 'relations' claim invalid or missing (expected array of objects with single item)")
	}

	orgURA, ok := relation["ura"].(string)
	if !ok || orgURA == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token 'relations[0].ura' claim invalid or missing (expected non-empty string)")
	}
	orgName, _ := relation["entity_name"].(string)

	userID := getString("dezi_nummer")
	if userID == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'dezi_nummer' claim")
	}
	initials := getString("initials")
	if initials == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'initials' claim")
	}
	surname := getString("surname")
	if surname == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'surname' claim")
	}
	surnamePrefix := getString("surname_prefix")
	if surnamePrefix == "" {
		return DeziIDTokenSubject{}, "", fmt.Errorf("id_token missing 'surname_prefix' claim")
	}

	// In 2024 format, roles is an array - we'll take the first role for now
	// TODO: Clarify how to handle multiple roles
	var role string
	rolesAny, ok := relation["roles"].([]any)
	if ok && len(rolesAny) > 0 {
		role, _ = rolesAny[0].(string)
	}

	return DeziIDTokenSubject{
		Identifier: orgURA,
		Name:       orgName,
		Employee: HealthcareWorker{
			Identifier:    userID,
			Initials:      initials,
			SurnamePrefix: surnamePrefix,
			Surname:       surname,
			Role:          role,
		},
	}, "2024", nil
}
