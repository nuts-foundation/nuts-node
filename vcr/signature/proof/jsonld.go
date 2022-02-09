package proof

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jws"
	ssi "github.com/nuts-foundation/go-did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"strings"
	"time"
)

// ProofOptions contains the options for a specific proof. When set they wil
type ProofOptions struct {
	// Created contains the date and time of signing. When not set, the current date time will be used.
	Created time.Time `json:"created"`
	// Domain property is used to associate a domain with a proof
	// https://w3c-ccg.github.io/security-vocab/#domain
	Domain *string `json:"domain,omitempty"`
	//The challenge property is used to associate a challenge with a proof
	// https://w3c-ccg.github.io/security-vocab/#challenge
	Challenge *string `json:"challenge,omitempty"`
	// The expirationDate property is used to associate an expirationDate with a proof
	ExpirationDate *time.Time `json:"expirationDate,omitempty"`
	// ProofPurpose contains a specific intent for the proof, the reason why an entity created it.
	// Acts as a safeguard to prevent the proof from being misused for a purpose other than the one it was intended for.
	ProofPurpose string `json:"proofPurpose"`
}

// ldProof contains the fields of the Proof data model: https://w3c-ccg.github.io/data-integrity-spec/#proofs
type LDProof struct {
	ProofOptions
	Nonce *string `json:"nonce,omitempty"`
	// Type contains the signature type. Its is determined from the key type.
	Type ssi.ProofType `json:"type"`
	// VerificationMethod is the key identifier for the public/private key pair used to sign this proof
	// should be resolvable, e.g. did:nuts:123#key-1
	VerificationMethod ssi.URI `json:"verificationMethod"`
	// proofValue holds the representation of the proof value.
	// This can be several keys, dependent on the suite like jws, proofValue or signatureValue
	//proofValue map[string]interface{}
	JWS        string      `json:"jws,omitempty"`
	ProofValue interface{} `json:"proofValue,omitempty"`
	Signature  interface{} `json:"signature,omitempty"`
}

func NewLDProof(options ProofOptions) *LDProof {
	return &LDProof{ProofOptions: options}
}

func NewLDProofFromDocumentProof(dp DocumentProof) (*LDProof, error) {
	proofBytes, err := json.Marshal(dp)
	if err != nil {
		return nil, err
	}
	result := &LDProof{}
	if err := json.Unmarshal(proofBytes, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (p LDProof) asMap() (map[string]interface{}, error) {
	proofBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	proofMap := map[string]interface{}{}
	if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
		return nil, err
	}
	proofMap["@context"] = determineProofContext(p.Type)
	proofMap["@type"] = proofMap["type"]
	return proofMap, nil
}

func (p LDProof) asCanonicalizableMap() (map[string]interface{}, error) {
	asMap, err := p.asMap()
	if err != nil {
		return nil, err
	}
	proofWithoutSignature := map[string]interface{}{}
	for key, value := range asMap {
		if key == "jws" || key == "signature" || key == "proofValue" {
			continue
		}
		proofWithoutSignature[key] = value
	}
	return proofWithoutSignature, nil
}

func (p LDProof) Verify(document interface{}, suite signature.Suite, key crypto.PublicKey) error {
	canonicalDocument, err := suite.CanonicalizeDocument(document)
	if err != nil {
		return nil
	}

	preparedProof, err := p.asCanonicalizableMap()
	if err != nil {
		return err
	}
	canonicalProof, err := suite.CanonicalizeDocument(preparedProof)
	if err != nil {
		return nil
	}

	tbv := append(suite.CalculateDigest(canonicalProof), suite.CalculateDigest(canonicalDocument)...)
	// the proof must be correct
	alg, err := nutsCrypto.SignatureAlgorithm(key)
	if err != nil {
		return err
	}

	jswVerifier, _ := jws.NewVerifier(alg)
	// the jws lib can't do this for us, so we concat hdr with payload for verification
	splittedJws := strings.Split(p.JWS, "..")
	if len(splittedJws) != 2 {
		return errors.New("invalid 'jws' value in proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], tbv)
	if err = jswVerifier.Verify([]byte(challenge), sig, key); err != nil {
		return fmt.Errorf("invalid proof signature: %w", err)
	}
	return nil
}

func (p *LDProof) Sign(document Document, suite signature.Suite, key nutsCrypto.Key) (interface{}, error) {
	p.Type = suite.GetType()
	p.ProofPurpose = "assertionMethod"
	p.Created = time.Now()
	vm, _ := ssi.ParseURI(key.KID())
	p.VerificationMethod = *vm

	canonicalDocument, err := suite.CanonicalizeDocument(document)
	if err != nil {
		return nil, err
	}

	canonicalProof, err := suite.CanonicalizeDocument(p.toMap())
	if err != nil {
		return nil, err
	}

	tbs := append(suite.CalculateDigest(canonicalProof), suite.CalculateDigest(canonicalDocument)...)

	if err != nil {
		return nil, err
	}

	sig, err := suite.Sign(tbs, key)
	if err != nil {
		return nil, err
	}

	detachedSignature := toDetachedSignature(string(sig))

	p.JWS = detachedSignature

	document["@context"] = append(document["@context"].([]interface{}), determineProofContext(suite.GetType()))
	document["proof"] = p
	return document, nil
}

func (p LDProof) toMap() map[string]interface{} {
	proofMap := map[string]interface{}{}
	p.copy(p, &proofMap)
	// Add the correct context to the proofMap for canonicalization
	proofMap["@context"] = determineProofContext(p.Type)
	proofMap["@type"] = proofMap["type"]
	return proofMap
}

const RsaSignature2018 = ssi.ProofType("RsaSignature2018")
const EcdsaSecp256k1Signature2019 = ssi.ProofType("EcdsaSecp256k1Signature2019")

func determineProofType(key nutsCrypto.Key) (ssi.ProofType, error) {
	//switch key.Public().(type) {
	//case *rsa.PublicKey:
	//	return RsaSignature2018, nil
	//case *ecdsa.PublicKey:
	//	return EcdsaSecp256k1Signature2019, nil
	//case *ed25519.PublicKey:
	return ssi.JsonWebSignature2020, nil
	////default:
	////	return "", errors.New("unknown key type")
	//}
}

func determineProofContext(proofType ssi.ProofType) string {
	switch proofType {
	case RsaSignature2018:
		return "https://w3id.org/security/v2"
	case ssi.JsonWebSignature2020:
		return "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
	case EcdsaSecp256k1Signature2019:
		return "https://w3id.org/security/v1"
	default:
		return ""
	}
}

// toDetachedSignature removes the middle part of the signature
func toDetachedSignature(sig string) string {
	splitted := strings.Split(sig, ".")
	return strings.Join([]string{splitted[0], splitted[2]}, "..")
}

func (LDProof) copy(a, b interface{}) error {
	byt, _ := json.Marshal(a)
	return json.Unmarshal(byt, b)
}

// CreateToBeSigned implements step 3 in the proof algorithm: https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
// Create a value tbs that represents the data to be signed, and set it to the result of running the Create Verify
// Hash Algorithm, passing the information in options.
func (p *LDProof) CreateToBeSigned(canonicalizedDocument interface{}, canonicalizedProof interface{}) ([]byte, error) {

	//https://w3c-ccg.github.io/data-integrity-spec/#create-verify-hash-algorithm
	// Step 4.2:
	// Hash canonicalized options document using the message digest algorithm (e.g. SHA-256) set output to the result.
	output := hash.SHA256Sum([]byte(canonicalizedProof.(string))).Slice()
	// Step 4.3:
	// Hash canonicalized document using the message digest algorithm (e.g. SHA-256) and append it to output.
	hashedDocument := hash.SHA256Sum([]byte(canonicalizedDocument.(string)))
	output = append(output, hashedDocument.Slice()...)

	// Step 5: Return output
	return output, nil
}
