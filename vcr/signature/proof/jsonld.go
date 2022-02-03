package proof

import (
	"encoding/json"
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
type ldProof struct {
	ProofOptions
	Nonce *string `json:"nonce,omitempty"`
	// Type contains the signature type. Its is determined from the key type.
	Type ssi.ProofType `json:"type"`
	// VerificationMethod is the key identifier for the public/private key pair used to sign this proof
	// should be resolvable, e.g. did:nuts:123#key-1
	VerificationMethod string `json:"verificationMethod"`
	// proofValue holds the representation of the proof value.
	// This can be several keys, dependent on the suite like jws, proofValue or signatureValue
	//proofValue map[string]interface{}
	JWS        string      `json:"jws,omitempty"`
	ProofValue interface{} `json:"proofValue,omitempty"`
	Signature  interface{} `json:"signature,omitempty"`
}

//func (p ldProof) MarshalJSON() ([]byte, error) {
//	type alias ldProof
//	tmp := alias(p)
//
//	bytes, err := json.Marshal(tmp)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(p.proofValue) == 0 {
//		return bytes, nil
//	}
//
//	asMap := map[string]interface{}{}
//	if err := json.Unmarshal(bytes, &asMap); err != nil {
//		return nil, err
//	}
//
//	for key, val := range p.proofValue {
//		asMap[key] = val
//	}
//
//	return json.Marshal(asMap)
//}

func NewLDProof(options ProofOptions) *ldProof {
	return &ldProof{ProofOptions: options}
}

//func (p *ldProof) SetProofValue(key string, value interface{}) {
//	p.proofValue[key] = value
//}
//
//func (p ldProof) GetProofValue(key string) interface{} {
//	return p.proofValue[key]
//}

//type ldProofBuilder struct {
//	ldDocumentLoader ld.DocumentLoader
//}
//
//func (b *ldProofBuilder) Sign(document Document, options ProofOptions, suite signature.Suite, key nutsCrypto.Key) (interface{}, error) {
//	proof := ldProof{ProofOptions: options}
//	proof.Sign(document, suite, key)
//}

//// NewLDProofBuilder creates a new ProofBuilder capable of generating LD-Proofs
//func NewLDProofBuilder() (*ldProofBuilder, error) {
//	loader := ld.NewCachingDocumentLoader(signature.NewEmbeddedFSDocumentLoader(assets.Assets, ld.NewDefaultDocumentLoader(nil)))
//	if err := loader.PreloadWithMapping(map[string]string{
//		"https://nuts.nl/credentials/v1":                                     "assets/contexts/nuts.ldjson",
//		"https://www.w3.org/2018/credentials/v1":                             "assets/contexts/w3c-credentials-v1.ldjson",
//		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": "assets/contexts/lds-jws2020-v1.ldjson",
//	}); err != nil {
//		return nil, fmt.Errorf("unable to preload nuts ld-context: %w", err)
//	}
//	return &ldProofBuilder{ldDocumentLoader: loader}, nil
//}

//
//func NewLDProofVerifier() (ProofVerifier, error) {
//	return newLDProofManager()
//}

// Verify implements the Proof Verification Algorithm: https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
//func (p ldProofManager) Verify(signedDocument interface{}, key crypto.PublicKey) error {
//	// 1)
//	// * Get the public key by dereferencing its URL identifier in the proof node of the default graph of signed document.
//	// TODO: acccept a keyResolver instead of thee key param?
//	// * Confirm that the unsigned data document that describes the public key specifies its controller and that its
//	//   controllers's URL identifier can be dereferenced to reveal a bi-directional link back to the key.
//	// TODO: is this needed?
//	// * Ensure that the key's controller is a trusted entity before proceeding to the next step.
//	// TODO: should this be done here, or be the responsibility of the caller?
//
//	// 2) Let document be a copy of signed document
//	document := map[string]interface{}{}
//	p.copy(signedDocument, &document)
//
//	// 3) Remove any proof nodes from the default graph in document and save it as proof
//	proof, ok := document["proof"]
//	if !ok {
//		return errors.New("no proof in document")
//	}
//	delete(document, "proof")
//
//	// 4) Generate a canonicalized document by canonicalizing document according to the canonicalization algorithm
//	// (e.g. the URDNA2015 [RDF-DATASET-C14N] algorithm).
//	canonicalizedDocument, err := p.canonicalize(document)
//	if err != nil {
//		return fmt.Errorf("unable to canonicalize document: %w", err)
//	}
//
//	// 5) Create a value tbv that represents the data to be verified, and set it to the result of running the
//	// Create-Verify-Hash Algorithm, passing the information in proof.
//	var tbv []byte
//	// Let proofMap be a copy of proof
//	proofMap := map[string]interface{}{}
//	p.copy(proof, &proofMap)
//	// If the proofValue parameter, such as jws, exists in proofMap, remove the entry
//	delete(proofMap, "jws")
//	// Add the correct context to the proofMap for canonicalization
//	rawProofType, ok := proofMap["type"]
//	if !ok {
//		return errors.New("missing type on proof")
//	}
//	proofType, ok := rawProofType.(string)
//	if !ok {
//		return errors.New("proof.type is not a string")
//	}
//	proofMap["@context"] = determineProofContext(ssi.ProofType(proofType))
//	proofMap["@type"] = proofMap["type"]
//	canonicalizedProof, err := p.canonicalize(proofMap)
//	if err != nil {
//		return fmt.Errorf("unable to canonicalize proof: %w", err)
//	}
//	if tbv, err = p.CreateToBeSigned(canonicalizedDocument, canonicalizedProof); err != nil {
//		return fmt.Errorf("unable to create bytes to verified")
//	}
//	// the proof must be correct
//	alg, err := nutsCrypto.SignatureAlgorithm(key)
//	if err != nil {
//		return err
//	}
//
//	verifier, _ := jws.NewVerifier(alg)
//	// the jws lib can't do this for us, so we concat hdr with payload for verification
//	splittedJws := strings.Split(proof.(map[string]interface{})["jws"].(string), "..")
//	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
//	challenge := fmt.Sprintf("%s.%s", splittedJws[0], tbv)
//	if err = verifier.Verify([]byte(challenge), sig, key); err != nil {
//		return fmt.Errorf("invalid proof signature: %w", err)
//	}
//
//	return nil
//}

func (p *ldProof) Sign(document Document, suite signature.Suite, key nutsCrypto.Key) (interface{}, error) {
	p.Type = suite.GetType()
	p.ProofPurpose = "assertionMethod"
	p.Created = time.Now()
	p.VerificationMethod = key.KID()

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

func (p ldProof) toMap() map[string]interface{} {
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

func (ldProof) copy(a, b interface{}) error {
	byt, _ := json.Marshal(a)
	return json.Unmarshal(byt, b)
}

// CreateToBeSigned implements step 3 in the proof algorithm: https://w3c-ccg.github.io/ld-proofs/#proof-algorithm
// Create a value tbs that represents the data to be signed, and set it to the result of running the Create Verify
// Hash Algorithm, passing the information in options.
func (p *ldProof) CreateToBeSigned(canonicalizedDocument interface{}, canonicalizedProof interface{}) ([]byte, error) {

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
