// Package ssiTypes provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.3 DO NOT EDIT.
package ssiTypes

// CredentialSubject Subject of a Verifiable Credential identifying the holder and expressing claims.
type CredentialSubject = interface{}

// DID DID according to Nuts specification
type DID = string

// DIDDocument A DID document according to the W3C spec following the Nuts Method rules as defined in [Nuts RFC006]
type DIDDocument struct {
	// Context The JSON-LD contexts that define the types used in this document. Can be a single string, or a list of strings.
	Context interface{} `json:"@context"`

	// AssertionMethod List of KIDs that may sign JWTs, JWSs and VCs
	AssertionMethod *[]string `json:"assertionMethod,omitempty"`

	// Authentication List of KIDs that may alter DID documents that they control
	Authentication *[]string `json:"authentication,omitempty"`

	// CapabilityDelegation List of KIDs that can be used to delegate capabilities that can be invoked using the DID document.
	CapabilityDelegation *[]string `json:"capabilityDelegation,omitempty"`

	// CapabilityInvocation List of KIDs that can be used for signing
	CapabilityInvocation *[]string `json:"capabilityInvocation,omitempty"`

	// Controller Single DID (as string) or List of DIDs that have control over the DID document
	Controller *interface{} `json:"controller,omitempty"`

	// Id DID according to Nuts specification
	Id DID `json:"id"`

	// KeyAgreement List of KIDs that can be used for encryption
	KeyAgreement *[]string `json:"keyAgreement,omitempty"`

	// Service List of supported services by the DID subject
	Service *[]Service `json:"service,omitempty"`

	// VerificationMethod list of keys
	VerificationMethod *[]VerificationMethod `json:"verificationMethod,omitempty"`
}

// DIDDocumentMetadata The DID document metadata.
type DIDDocumentMetadata struct {
	// Created Time when DID document was created in rfc3339 form.
	Created string `json:"created"`

	// Deactivated Whether the DID document has been deactivated.
	Deactivated bool `json:"deactivated"`

	// Hash Sha256 in hex form of the DID document contents.
	Hash string `json:"hash"`

	// PreviousHash Sha256 in hex form of the previous version of this DID document.
	PreviousHash *string `json:"previousHash,omitempty"`

	// Txs txs lists the transaction(s) that created the current version of this DID Document.
	// If multiple transactions are listed, the DID Document is conflicted
	Txs []string `json:"txs"`

	// Updated Time when DID document was updated in rfc3339 form.
	Updated *string `json:"updated,omitempty"`
}

// EmbeddedProof Cryptographic proofs that can be used to detect tampering and verify the authorship of a
// credential or presentation. An embedded proof is a mechanism where the proof is included in
// the data, such as a Linked Data Signature.
type EmbeddedProof struct {
	// Challenge A random or pseudo-random value, provided by the verifier, used by some authentication protocols to
	// mitigate replay attacks.
	Challenge *string `json:"challenge,omitempty"`

	// Created Date and time at which proof has been created.
	Created string `json:"created"`

	// Domain A string value that specifies the operational domain of a digital proof. This could be an Internet domain
	// name like example.com, an ad-hoc value such as mycorp-level3-access, or a very specific transaction value
	// like 8zF6T$mqP. A signer could include a domain in its digital proof to restrict its use to particular
	// target, identified by the specified domain.
	Domain *string `json:"domain,omitempty"`

	// Jws JSON Web Signature
	Jws string `json:"jws"`

	// Nonce A unique string value generated by the holder, MUST only be used once for a particular domain
	// and window of time. This value can be used to mitigate replay attacks.
	Nonce *string `json:"nonce,omitempty"`

	// ProofPurpose It expresses the purpose of the proof and ensures the information is protected by the
	// signature.
	ProofPurpose string `json:"proofPurpose"`

	// Type Type of the object or the datatype of the typed value. Currently only supported value is "JsonWebSignature2020".
	Type string `json:"type"`

	// VerificationMethod Specifies the public key that can be used to verify the digital signature.
	// Dereferencing a public key URL reveals information about the controller of the key,
	// which can be checked against the issuer of the credential.
	VerificationMethod string `json:"verificationMethod"`
}

// Revocation Credential revocation record
type Revocation struct {
	// Date date is a rfc3339 formatted datetime.
	Date string `json:"date"`

	// Issuer DID according to Nuts specification
	Issuer DID `json:"issuer"`

	// Proof Proof contains the cryptographic proof(s).
	Proof *map[string]interface{} `json:"proof,omitempty"`

	// Reason reason describes why the VC has been revoked
	Reason *string `json:"reason,omitempty"`

	// Subject subject refers to the credential identifier that is revoked (not the credential subject)
	Subject string `json:"subject"`
}

// Service A service supported by a DID subject.
type Service struct {
	// Id ID of the service.
	Id string `json:"id"`

	// ServiceEndpoint Either a URI or a complex object.
	ServiceEndpoint interface{} `json:"serviceEndpoint"`

	// Type The type of the endpoint.
	Type string `json:"type"`
}

// VerifiableCredential A credential according to the W3C and Nuts specs.
type VerifiableCredential struct {
	// Context List of URIs of JSON-LD contexts of the VC.
	Context interface{} `json:"@context"`

	// CredentialSubject Subject of a Verifiable Credential identifying the holder and expressing claims.
	CredentialSubject CredentialSubject `json:"credentialSubject"`

	// ExpirationDate rfc3339 time string until when the credential is valid.
	ExpirationDate *string `json:"expirationDate,omitempty"`

	// Id Credential ID. An URI which uniquely identifies the credential e.g. the issuers DID concatenated with an UUID.
	Id *string `json:"id,omitempty"`

	// IssuanceDate rfc3339 time string when the credential was issued.
	IssuanceDate string `json:"issuanceDate"`

	// Issuer DID according to Nuts specification
	Issuer DID `json:"issuer"`

	// Proof one or multiple cryptographic proofs
	Proof interface{} `json:"proof"`

	// Type A single string or array of strings. The value(s) indicate the type of credential. It should contain `VerifiableCredential`. Each type should be defined in the @context.
	Type []string `json:"type"`
}

// VerifiablePresentation Verifiable Presentation
type VerifiablePresentation struct {
	// Context An ordered set where the first item is a URI https://www.w3.org/2018/credentials/v1. It is used to define
	// terms and help to express specific identifiers in a compact manner.
	Context interface{} `json:"@context"`

	// Holder URI of the entity that is generating the presentation.
	Holder *string `json:"holder,omitempty"`

	// Id URI that is used to unambiguously refer to an object, such as a person, product, or organization.
	Id *string `json:"id,omitempty"`

	// Proof Cryptographic proofs that can be used to detect tampering and verify the authorship of a
	// credential or presentation. An embedded proof is a mechanism where the proof is included in
	// the data, such as a Linked Data Signature.
	Proof *interface{} `json:"proof,omitempty"`

	// Type A single string or array of strings. Values indicate the type of object. It should contain `VerifiablePresentation`. Each type must be defined in the @context.
	Type interface{} `json:"type"`

	// VerifiableCredential VerifiableCredential is composed of a list containing one or more verifiable credentials, in a
	// cryptographically verifiable format.
	VerifiableCredential *interface{} `json:"verifiableCredential,omitempty"`
}

// VerificationMethod A public key in JWK form.
type VerificationMethod struct {
	// Controller The DID subject this key belongs to.
	Controller string `json:"controller"`

	// Id The ID of the key, used as KID in various JWX technologies.
	Id string `json:"id"`

	// PublicKeyJwk The public key formatted according rfc7517.
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk"`

	// Type The type of the key.
	Type string `json:"type"`
}
