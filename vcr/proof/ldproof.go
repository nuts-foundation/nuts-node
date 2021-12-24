package proof

import (
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/piprate/json-gold/ld"
	"strings"
	"time"
)

type ProofOptions struct {
	// Created contains the current date and time of signing
	Type      string     `json:"type"`
	Created   time.Time  `json:"created"`
	Domain    *string    `json:"domain,omitempty"`
	Nonce     *string    `json:"nonce,omitempty"`
	Challenge *string    `json:"challenge,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
}

// ProofBuilder defines a generic interface for proof builders.
type ProofBuilder interface {
	// Sign accepts a
	Sign(key crypto.Key) (interface{}, error)
}

// LDProof with a detached JWS signature.
type LDProof struct {
	ProofOptions
	// KID is the identifier for the public/private key pair used to sign this proof
	KID string `json:"kid"`
	// JWS contains the proofValue for a detached signature
	JWS *string `json:"jws,omitempty"`
}

type ldProofBuilder struct {
	input   interface{}
	options ProofOptions
}

func NewLDProofBuilder(document interface{}, options ProofOptions) ldProofBuilder {
	return ldProofBuilder{
		input:   document,
		options: options,
	}
}

func (p ldProofBuilder) Sign(key crypto.Key) (interface{}, error) {
	var (
		normalizedDoc interface{}
		tbs           []byte
		err           error
	)
	resultingProof := new(LDProof)

	if err = p.copy(p.options, &resultingProof.ProofOptions); err != nil {
		return nil, fmt.Errorf("could not deep-copy proofOptons: %w", err)
	}

	// Set some default values;
	// Step 3 of https://w3c-ccg.github.io/ld-proofs/#create-verify-hash-algorithm
	// If created does not exist in options, add an entry with a value that is an [ISO8601] combined date and time
	// string containing the current date and time accurate to at least one second
	if resultingProof.ProofOptions.Created.IsZero() {
		resultingProof.ProofOptions.Created = time.Now()
	}
	resultingProof.KID = key.KID()

	if normalizedDoc, err = p.canonicalize(p.input); err != nil {
		return nil, fmt.Errorf("unable to canonicalize ldProof: %w", err)
	}

	if tbs, err = p.CreateToBeSigned(normalizedDoc, resultingProof.ProofOptions); err != nil {
		return nil, fmt.Errorf("unable to create bytes to be signed")
	}

	sig, err := crypto.SignJWS(tbs, detachedJWSHeaders(), key.Signer())
	if err != nil {
		return nil, fmt.Errorf("unable to sign ldProof: %w", err)
	}

	// Remove payload from jws
	detachedSignature := toDetachedSignature(sig)

	resultingProof.JWS = &detachedSignature

	return resultingProof, nil
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

func (ldProofBuilder) copy(a, b interface{}) error {
	byt, _ := json.Marshal(a)
	return json.Unmarshal(byt, b)
}

// canonicalize canonicalizes the json-ld input according to the URDNA2015 [RDF-DATASET-NORMALIZATION] algorithm.
func (p *ldProofBuilder) canonicalize(input interface{}) (result interface{}, err error) {
	var optionsMap map[string]interface{}
	inputAsJson, _ := json.Marshal(input)
	json.Unmarshal(inputAsJson, &optionsMap)
	proc := ld.NewJsonLdProcessor()

	normalizeOptions := ld.NewJsonLdOptions("")
	loader := ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(nil))
	if err = loader.PreloadWithMapping(map[string]string{
		"https://nuts.nl/credentials/v1":                                     "./assets/contexts/nuts.ldjson",
		"https://www.w3.org/2018/credentials/v1":                             "./assets/contexts/w3c-credentials-v1.ldjson",
		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": "./assets/contexts/lds-jws2020-v1.ldjson",
	}); err != nil {
		return nil, fmt.Errorf("unable to preload nuts ld-context: %w", err)
	}
	normalizeOptions.DocumentLoader = loader
	normalizeOptions.Format = "application/n-quads"
	normalizeOptions.Algorithm = "URDNA2015"

	result, err = proc.Normalize(optionsMap, normalizeOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to normalize document: %w", err)
	}

	log.Logger().Infof("canonicalize document %s", result)
	return
}

const JsonWebSignature2020 = "JsonWebSignature2020"

// CreateToBeSigned implements step 3 in the proof algorithm: https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
// Create a value tbs that represents the data to be signed, and set it to the result of running the Create Verify
// Hash Algorithm, passing the information in options.
func (p *ldProofBuilder) CreateToBeSigned(canonicalizedDocument interface{}, proofOptions ProofOptions) ([]byte, error) {

	// Step 4.1 of https://w3c-ccg.github.io/ld-proofs/#create-verify-hash-algorithm:
	// Creating a canonicalized options document by canonicalizing options according to the canonicalization algorithm
	// (e.g. the URDNA2015 [RDF-DATASET-NORMALIZATION] algorithm).

	// prepare proofOptions for JSON-LD normalizing
	var optionsMap map[string]interface{}
	optionsAsJson, _ := json.Marshal(proofOptions)
	json.Unmarshal(optionsAsJson, &optionsMap)
	optionsMap["@context"] = "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
	optionsMap["@type"] = optionsMap["type"]
	canonicalizedOptions, err := p.canonicalize(optionsMap)
	if err != nil {
		return nil, fmt.Errorf("unable to normalize document: %w", err)
	}

	// Step 4.2:
	// Hash canonicalized options document using the message digest algorithm (e.g. SHA-256) set output to the result.
	output := hash.SHA256Sum([]byte(canonicalizedOptions.(string))).Slice()
	// Step 4.3:
	// Hash canonicalized document using the message digest algorithm (e.g. SHA-256) and append it to output.
	hashedDocument := hash.SHA256Sum([]byte(canonicalizedDocument.(string)))
	output = append(output, hashedDocument.Slice()...)

	// Step 5: Return output
	return output, nil
}
