package proof

import (
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/piprate/json-gold/ld"
	"strings"
	"time"
)

type ProofOptions struct {
	//KID is the identifier for the public/private key pair
	KID string `json:"kid"`
	// Created contains the current date and time of signing
	Type      string     `json:"type"`
	Created   time.Time  `json:"created"`
	Domain    *string    `json:"domain,omitempty"`
	Nonce     *string    `json:"nonce,omitempty"`
	JWS       *string    `json:"jws,omitempty"`
	Challenge *string    `json:"challenge,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
}

type LDProof struct {
	input                 interface{}
	output                interface{}
	options               ProofOptions
	canonicalizedDocument interface{}
	// tbs represents the data to be signed
	tbs        []byte
	proofValue []byte
}

func NewLDProof(document interface{}, options ProofOptions) LDProof {
	return LDProof{
		input:   document,
		options: options,
	}
}

func (p LDProof) Sign(key crypto.Key) (proof interface{}, err error) {
	if err = p.Copy(); err != nil {
		return
	}
	if err = p.Canonicalize(); err != nil {
		return
	}

	if err = p.CreateToBeSigned(); err != nil {
		return
	}

	sig, err := crypto.SignJWS(p.tbs, detachedJWSHeaders(), key.Signer())
	if err != nil {
		return
	}
	// Remove payload from jws
	detachedSignature := toDetachedSignature(sig)

	p.options.JWS = &detachedSignature
	proof = p.options

	return
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

func (p *LDProof) Copy() error {
	p.output = p.input // TODO: create a deep copy
	return nil
}

func (p *LDProof) Canonicalize() (err error) {
	proc := ld.NewJsonLdProcessor()
	normalizeOptions := ld.NewJsonLdOptions("")
	normalizeOptions.Format = "application/n-quads"
	normalizeOptions.Algorithm = "URDNA2015"

	normalizedDoc, err := proc.Normalize(p.input, normalizeOptions)
	if err != nil {
		return fmt.Errorf("unable to normalize document: %w", err)
	}
	p.canonicalizedDocument = normalizedDoc
	return nil
}

const JsonWebSignature2020 = "JsonWebSignature2020"

func (p *LDProof) CreateToBeSigned() (err error) {
	options := p.options
	// Set some default values;
	if options.Created.IsZero() {
		options.Created = time.Now()
	}

	var optionsMap map[string]interface{}
	optionsAsJson, _ := json.Marshal(options)
	json.Unmarshal(optionsAsJson, &optionsMap)
	optionsMap["@context"] = "https://www.w3.org/2018/credentials/v1"

	proc := ld.NewJsonLdProcessor()
	jsonLDOptions := ld.NewJsonLdOptions("")
	jsonLDOptions.Format = "application/n-quads"
	jsonLDOptions.Algorithm = "URDNA2015"

	normalizedOptions, err := proc.Normalize(optionsMap, jsonLDOptions)
	if err != nil {
		return fmt.Errorf("unable to normalize document: %w", err)
	}

	hashedOptions := hash.SHA256Sum([]byte(normalizedOptions.(string)))
	hashedDocument := hash.SHA256Sum([]byte(p.canonicalizedDocument.(string)))
	p.tbs = append(hashedOptions.Slice(), hashedDocument.Slice()...)

	return nil
}
