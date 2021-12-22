package presentation

import "github.com/nuts-foundation/go-did/vc"

// Verifiable Presentation
type VerifiablePresentation struct {
	// An ordered set where the first item is a URI https://www.w3.org/2018/credentials/v1. It is used to define
	// terms and help to express specific identifiers in a compact manner.
	Context []string `json:"@context"`

	// URI of the entity that is generating the presentation.
	Holder *string `json:"holder,omitempty"`

	// URI that is used to unambiguously refer to an object, such as a person, product, or\norganization.
	Id *string `json:"id,omitempty"`

	// Cryptographic proofs that can be used to detect tampering and verify the authorship of a
	// credential or presentation. An embedded proof is a mechanism where the proof is included in
	// the data, such as a Linked Data Signature.
	Proof interface{} `json:"proof,omitempty"`

	// Type of the object or the datatype of the typed value.
	Type []string `json:"type"`

	// VerifiableCredential is composed of a list containing one or more verifiable credentials, in a
	// cryptographically verifiable format.
	VerifiableCredential *[]vc.VerifiableCredential `json:"verifiableCredential,omitempty"`
}
