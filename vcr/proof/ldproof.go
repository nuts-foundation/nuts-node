package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jws"
	ssi "github.com/nuts-foundation/go-did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	_ "github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/piprate/json-gold/ld"
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
}

// ProofBuilder defines a generic interface for proof builders.
type ProofBuilder interface {
	// Sign accepts a key and returns the signed document.
	Sign(key nutsCrypto.Key) (interface{}, error)
}

type ProofVerifier interface {
	// Verify verifies the signedDocument with the provided public key. If the document is valid, it returns no error.
	Verify(signedDocument interface{}, key crypto.PublicKey) error
}

// LDProof with a detached JWS signature.
type LDProof struct {
	ProofOptions
	Nonce *string `json:"nonce,omitempty"`
	// Type contains the signature type. Its is determined from the key type.
	Type ssi.ProofType `json:"type"`
	// VerificationMethod is the key identifier for the public/private key pair used to sign this proof
	// should be resolvable, e.g. did:nuts:123#key-1
	VerificationMethod string `json:"verificationMethod"`
	// JWS contains the proofValue for a detached signature
	JWS *string `json:"jws,omitempty"`
}

type ldProofManager struct {
	input            interface{}
	options          ProofOptions
	ldDocumentLoader ld.DocumentLoader
}

func newLDProofManager() (*ldProofManager, error) {
	loader := ld.NewCachingDocumentLoader(NewEmbeddedFSDocumentLoader(assets.Assets, ld.NewDefaultDocumentLoader(nil)))
	if err := loader.PreloadWithMapping(map[string]string{
		"https://nuts.nl/credentials/v1":                                     "assets/contexts/nuts.ldjson",
		"https://www.w3.org/2018/credentials/v1":                             "assets/contexts/w3c-credentials-v1.ldjson",
		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": "assets/contexts/lds-jws2020-v1.ldjson",
	}); err != nil {
		return nil, fmt.Errorf("unable to preload nuts ld-context: %w", err)
	}
	return &ldProofManager{ldDocumentLoader: loader}, nil
}

// NewLDProofBuilder creates a new ProofBuilder capable of generating LD-Proofs
func NewLDProofBuilder(document interface{}, options ProofOptions) (ProofBuilder, error) {
	proofManager, err := newLDProofManager()
	if err != nil {
		return nil, err
	}
	proofManager.input = document
	proofManager.options = options

	return proofManager, nil
}

func NewLDProofVerifier() (ProofVerifier, error) {
	return newLDProofManager()
}

// Verify implements the Proof Verification Algorithm: https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
func (p ldProofManager) Verify(signedDocument interface{}, key crypto.PublicKey) error {
	// 1)
	// * Get the public key by dereferencing its URL identifier in the proof node of the default graph of signed document.
	// TODO: acccept a keyResolver instead of thee key param?
	// * Confirm that the unsigned data document that describes the public key specifies its controller and that its
	//   controllers's URL identifier can be dereferenced to reveal a bi-directional link back to the key.
	// TODO: is this needed?
	// * Ensure that the key's controller is a trusted entity before proceeding to the next step.
	// TODO: should this be done here, or be the responsibility of the caller?

	// 2) Let document be a copy of signed document
	document := map[string]interface{}{}
	p.copy(signedDocument, &document)

	// 3) Remove any proof nodes from the default graph in document and save it as proof
	proof, ok := document["proof"]
	if !ok {
		return errors.New("no proof in document")
	}
	delete(document, "proof")

	// 4) Generate a canonicalized document by canonicalizing document according to the canonicalization algorithm
	// (e.g. the URDNA2015 [RDF-DATASET-C14N] algorithm).
	canonicalizedDocument, err := p.canonicalize(document)
	if err != nil {
		return fmt.Errorf("unable to canonicalize document: %w", err)
	}

	// 5) Create a value tbv that represents the data to be verified, and set it to the result of running the
	// Create-Verify-Hash Algorithm, passing the information in proof.
	var tbv []byte
	// Let proofMap be a copy of proof
	proofMap := map[string]interface{}{}
	p.copy(proof, &proofMap)
	// If the proofValue parameter, such as jws, exists in proofMap, remove the entry
	delete(proofMap, "jws")
	// Add the correct context to the proofMap for canonicalization
	rawProofType, ok := proofMap["type"]
	if !ok {
		return errors.New("missing type on proof")
	}
	proofType, ok := rawProofType.(string)
	if !ok {
		return errors.New("proof.type is not a string")
	}
	proofMap["@context"] = determineProofContext(ssi.ProofType(proofType))
	proofMap["@type"] = proofMap["type"]
	canonicalizedProof, err := p.canonicalize(proofMap)
	if err != nil {
		return fmt.Errorf("unable to canonicalize proof: %w", err)
	}
	if tbv, err = p.CreateToBeSigned(canonicalizedDocument, canonicalizedProof); err != nil {
		return fmt.Errorf("unable to create bytes to verified")
	}
	// the proof must be correct
	alg, err := nutsCrypto.SignatureAlgorithm(key)
	if err != nil {
		return err
	}

	verifier, _ := jws.NewVerifier(alg)
	// the jws lib can't do this for us, so we concat hdr with payload for verification
	splittedJws := strings.Split(proof.(map[string]interface{})["jws"].(string), "..")
	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], tbv)
	if err = verifier.Verify([]byte(challenge), sig, key); err != nil {
		return fmt.Errorf("invalid proof signature: %w", err)
	}

	return nil
}

// Sign returns a *LDProof containing the LD-Proof for the input document.
func (p ldProofManager) Sign(key nutsCrypto.Key) (interface{}, error) {
	var (
		normalizedDoc   interface{}
		normalizedProof interface{}
		tbs             []byte
		err             error
	)

	// copy the proof options into the LDProof
	resultingProof := new(LDProof)
	if err = p.copy(p.options, &resultingProof.ProofOptions); err != nil {
		return nil, fmt.Errorf("could not deep-copy proofOptons: %w", err)
	}

	// Set some default values for the resulting proof;
	// Step 3 of https://w3c-ccg.github.io/ld-proofs/#create-verify-hash-algorithm
	// If created does not exist in options, add an entry with a value that is an [ISO8601] combined date and time
	// string containing the current date and time accurate to at least one second
	if resultingProof.ProofOptions.Created.IsZero() {
		resultingProof.ProofOptions.Created = time.Now()
	}
	resultingProof.VerificationMethod = key.KID()

	// nonce Needs to be unique so the verifier can store it during the duration the presentation is valid.
	uuidNonce := uuid.New().String()
	resultingProof.Nonce = &uuidNonce

	// The type is dependent on the key type.
	resultingProof.Type, err = determineProofType(key)
	if err != nil {
		return nil, fmt.Errorf("could not determine proof type: %w", err)
	}

	// copy the document
	documentMap := map[string]interface{}{}
	p.copy(p.input, &documentMap)
	if normalizedDoc, err = p.canonicalize(documentMap); err != nil {
		return nil, fmt.Errorf("unable to canonicalize input document: %w", err)
	}

	// Step 4.1 of https://w3c-ccg.github.io/ld-proofs/#create-verify-hash-algorithm:
	// Creating a canonicalized options document by canonicalizing options according to the canonicalization algorithm
	// (e.g. the URDNA2015 [RDF-DATASET-NORMALIZATION] algorithm).
	proofMap := p.toProofMap(*resultingProof)
	if normalizedProof, err = p.canonicalize(proofMap); err != nil {
		return nil, fmt.Errorf("unable to canonicalize document: %w", err)
	}

	if tbs, err = p.CreateToBeSigned(normalizedDoc, normalizedProof); err != nil {
		return nil, fmt.Errorf("unable to create bytes to be signed")
	}

	sig, err := nutsCrypto.SignJWS(tbs, detachedJWSHeaders(), key.Signer())
	if err != nil {
		return nil, fmt.Errorf("unable to sign ldProof: %w", err)
	}

	// Remove payload from jws
	detachedSignature := toDetachedSignature(sig)

	resultingProof.JWS = &detachedSignature

	documentMap["@context"] = append(documentMap["@context"].([]interface{}), determineProofContext(resultingProof.Type))
	documentMap["proof"] = resultingProof
	return documentMap, nil
}

func (p ldProofManager) toProofMap(proof LDProof) map[string]interface{} {
	proofMap := map[string]interface{}{}
	p.copy(proof, &proofMap)
	// Add the correct context to the proofMap for canonicalization
	proofMap["@context"] = determineProofContext(proof.Type)
	proofMap["@type"] = proofMap["type"]
	return proofMap
}

const RsaSignature2018 = ssi.ProofType("RsaSignature2018")
const EcdsaSecp256k1Signature2019 = ssi.ProofType("EcdsaSecp256k1Signature2019")

func determineProofType(key nutsCrypto.Key) (ssi.ProofType, error) {
	switch key.Public().(type) {
	case *rsa.PublicKey:
		return RsaSignature2018, nil
	case *ecdsa.PublicKey:
		return EcdsaSecp256k1Signature2019, nil
	case *ed25519.PublicKey:
		return ssi.JsonWebSignature2020, nil
	default:
		return "", errors.New("unknown key type")
	}
}

func determineProofContext(proofType ssi.ProofType) string {
	switch proofType {
	case RsaSignature2018:
		return "https://w3id.org/security/v1"
	case ssi.JsonWebSignature2020:
		return "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
	case EcdsaSecp256k1Signature2019:
		return "https://w3id.org/security/v2"
	default:
		return ""
	}
}

// detachedJWSHeaders creates headers for JsonWebSignature2020
// the alg will be based upon the key
// {"b64":false,"crit":["b64"]}
func detachedJWSHeaders() map[string]interface{} {
	return map[string]interface{}{
		"b64":  false,
		"crit": []string{"b64"},
	}
}

// toDetachedSignature removes the middle part of the signature
func toDetachedSignature(sig string) string {
	splitted := strings.Split(sig, ".")
	return strings.Join([]string{splitted[0], splitted[2]}, "..")
}

func (ldProofManager) copy(a, b interface{}) error {
	byt, _ := json.Marshal(a)
	return json.Unmarshal(byt, b)
}

// canonicalize canonicalizes the json-ld input according to the URDNA2015 [RDF-DATASET-NORMALIZATION] algorithm.
func (p *ldProofManager) canonicalize(input interface{}) (result interface{}, err error) {
	var optionsMap map[string]interface{}
	inputAsJson, _ := json.Marshal(input)
	json.Unmarshal(inputAsJson, &optionsMap)
	proc := ld.NewJsonLdProcessor()

	normalizeOptions := ld.NewJsonLdOptions("")
	normalizeOptions.DocumentLoader = p.ldDocumentLoader
	normalizeOptions.Format = "application/n-quads"
	normalizeOptions.Algorithm = "URDNA2015"

	result, err = proc.Normalize(optionsMap, normalizeOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to normalize document: %w", err)
	}

	fmt.Println("BEGIN: canonicalized doc:")
	fmt.Print(result)
	fmt.Println("END")
	return
}

// CreateToBeSigned implements step 3 in the proof algorithm: https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
// Create a value tbs that represents the data to be signed, and set it to the result of running the Create Verify
// Hash Algorithm, passing the information in options.
func (p *ldProofManager) CreateToBeSigned(canonicalizedDocument interface{}, canonicalizedProof interface{}) ([]byte, error) {

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
