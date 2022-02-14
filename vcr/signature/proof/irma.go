package proof

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	ssi "github.com/nuts-foundation/go-did"
	irma "github.com/privacybydesign/irmago"
)

// NutsIRMASignatureProof2022 is a Proof type.
// https://nuts-foundation.gitbook.io/drafts/rfc/rfc013-vc-irma-proof#3.1-type
const NutsIRMASignatureProof2022 = ssi.ProofType("NutsIRMASignatureProof2022")

// IRMASignatureProof is the proof of a Verifiable Credential containing an embedded IRMA signature
type IRMASignatureProof struct {
	// Type defines the specific proof type used (in this case `NutsIRMASignatureProof2022`)
	Type ssi.ProofType `json:"type"`

	// ProofValue contains the base64 encoded IRMA signature
	ProofValue string `json:"proofValue"`
}

// Verify verifies the IRMA signature and returns the attributes that are present
func (proof IRMASignatureProof) Verify(config *irma.Configuration) (map[string]string, error) {
	if proof.Type != NutsIRMASignatureProof2022 {
		return nil, fmt.Errorf("invalid proof type: %s", proof.Type)
	}

	data, err := base64.StdEncoding.DecodeString(proof.ProofValue)
	if err != nil {
		return nil, err
	}

	msg := &irma.SignedMessage{}

	if err := json.Unmarshal(data, msg); err != nil {
		return nil, err
	}

	attributes, status, err := msg.Verify(config, nil)
	if err != nil {
		return nil, err
	}

	if status != irma.ProofStatusValid {
		return nil, fmt.Errorf("invalid status: %s", status)
	}

	attrs := make(map[string]string)

	for _, group := range attributes {
		for _, attr := range group {
			id := attr.Identifier.String()

			if attr.Status != irma.AttributeProofStatusPresent &&
				attr.Status != irma.AttributeProofStatusExtra {
				return nil, fmt.Errorf("attribute %s not valid", id)
			}

			if attr.RawValue == nil {
				return nil, fmt.Errorf("attribute %s has no value", id)
			}

			attrs[id] = *attr.RawValue
		}
	}

	return attrs, nil
}
