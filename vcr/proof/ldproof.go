package proof

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	_ "github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/piprate/json-gold/ld"
	"net/url"
	"strings"
	"time"
)

type ProofOptions struct {
	// Created contains the current date and time of signing
	Created   time.Time  `json:"created"`
	Domain    *string    `json:"domain,omitempty"`
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
	Nonce *string `json:"nonce,omitempty"`
	// Type contains the signature type. Its is determined from the key type.
	Type ssi.ProofType `json:"type"`
	// VerificationMethod is the key identifier for the public/private key pair used to sign this proof
	// should be resolvable, e.g. did:nuts:123#key-1
	VerificationMethod string `json:"verificationMethod"`
	// JWS contains the proofValue for a detached signature
	JWS *string `json:"jws,omitempty"`
}

type ldProofBuilder struct {
	input            interface{}
	options          ProofOptions
	ldDocumentLoader ld.DocumentLoader
}

type embeddedFSDocumentLoader struct {
	fs         embed.FS
	nextLoader ld.DocumentLoader
}

func NewEmbeddedFSDocumentLoader(fs embed.FS, nextLoader ld.DocumentLoader) *embeddedFSDocumentLoader {
	return &embeddedFSDocumentLoader{
		fs:         fs,
		nextLoader: nextLoader,
	}
}

func (e embeddedFSDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, fmt.Sprintf("error parsing URL: %s", u))
	}

	protocol := parsedURL.Scheme
	if protocol != "http" && protocol != "https" {
		remoteDoc := &ld.RemoteDocument{}
		file, err := e.fs.Open(u)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		defer file.Close()
		remoteDoc.Document, err = ld.DocumentFromReader(file)
		if err != nil {
			return nil, ld.NewJsonLdError(ld.LoadingDocumentFailed, err)
		}
		return remoteDoc, nil
	}
	return e.nextLoader.LoadDocument(u)
}

func NewLDProofBuilder(document interface{}, options ProofOptions) (*ldProofBuilder, error) {
	loader := ld.NewCachingDocumentLoader(NewEmbeddedFSDocumentLoader(assets.Assets, ld.NewDefaultDocumentLoader(nil)))
	if err := loader.PreloadWithMapping(map[string]string{
		"https://nuts.nl/credentials/v1":                                     "assets/contexts/nuts.ldjson",
		"https://www.w3.org/2018/credentials/v1":                             "assets/contexts/w3c-credentials-v1.ldjson",
		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": "assets/contexts/lds-jws2020-v1.ldjson",
	}); err != nil {
		return nil, fmt.Errorf("unable to preload nuts ld-context: %w", err)
	}
	return &ldProofBuilder{
		input:            document,
		options:          options,
		ldDocumentLoader: loader,
	}, nil
}

// Sign returns a *LDProof containing the LD-Proof for the input document.
func (p ldProofBuilder) Sign(key crypto.Key) (interface{}, error) {
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

	sig, err := crypto.SignJWS(tbs, detachedJWSHeaders(), key.Signer())
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

func (p ldProofBuilder) toProofMap(proof LDProof) map[string]interface{} {
	proofMap := map[string]interface{}{}
	p.copy(proof, &proofMap)
	// Add the correct context to the proofMap for canonicalization
	proofMap["@context"] = determineProofContext(proof.Type)
	proofMap["@type"] = proofMap["type"]
	return proofMap
}

const RsaSignature2018 = ssi.ProofType("RsaSignature2018")
const EcdsaSecp256k1Signature2019 = ssi.ProofType("EcdsaSecp256k1Signature2019")

func determineProofType(key crypto.Key) (ssi.ProofType, error) {
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
	normalizeOptions.DocumentLoader = p.ldDocumentLoader
	normalizeOptions.Format = "application/n-quads"
	normalizeOptions.Algorithm = "URDNA2015"

	result, err = proc.Normalize(optionsMap, normalizeOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to normalize document: %w", err)
	}

	log.Logger().Infof("canonicalize document %s", result)
	return
}

// CreateToBeSigned implements step 3 in the proof algorithm: https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
// Create a value tbs that represents the data to be signed, and set it to the result of running the Create Verify
// Hash Algorithm, passing the information in options.
func (p *ldProofBuilder) CreateToBeSigned(canonicalizedDocument interface{}, canonicalizedProof interface{}) ([]byte, error) {

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
