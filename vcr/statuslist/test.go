package statuslist

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"testing"
	"time"
)

func ValidStatusList2021Credential(_ testing.TB) vc.VerifiableCredential {
	id := ssi.MustParseURI("https://example.com/credentials/status/3")
	validFrom := time.Now()
	validUntilTomorrow := validFrom.Add(24 * time.Hour)
	return vc.VerifiableCredential{
		Context:          []ssi.URI{vc.VCContextV1URI(), statusList2021ContextURI},
		ID:               &id,
		Type:             []ssi.URI{vc.VerifiableCredentialTypeV1URI(), credential.stringToURI(StatusList2021CredentialType)},
		Issuer:           ssi.MustParseURI("did:example:12345"),
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntilTomorrow,
		CredentialStatus: nil,
		CredentialSubject: []any{&StatusList2021CredentialSubject{
			Id:            "https://example-com/status/3#list",
			Type:          StatusList2021CredentialSubjectType,
			StatusPurpose: "revocation",
			EncodedList:   "H4sIAAAAAAAA_-zAsQAAAAACsNDypwqjZ2sAAAAAAAAAAAAAAAAAAACAtwUAAP__NxdfzQBAAAA=", // has bit 1 set to true
		}},
		Proof: []any{vc.Proof{}},
	}
}
