package didweb

import (
	"context"
	crypt "crypto"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vdr/events"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/sql"
)

var _ events.MethodManager = (*Manager)(nil)

func (m Manager) GenerateDocument(ctx context.Context, subject string, keyTypes management.DIDKeyFlags) (*did.Document, error) {
	var newDID *did.DID
	var err error
	if subject == "" {
		newDID = &m.rootDID
	}
	if newDID == nil {
		newDID, _ = did.ParseDID(fmt.Sprintf("%s:iam:%s", m.rootDID.String(), uuid.New()))
	}
	// private key stored in keystore
	verificationMethod, err := m.GenerateVerificationMethod(ctx, *newDID)
	if err != nil {
		return nil, err
	}
	document, err := buildDocument(*newDID, *verificationMethod, keyTypes)
	return &document, err
}

func (m Manager) GenerateVerificationMethod(ctx context.Context, controller did.DID) (*did.VerificationMethod, error) {
	verificationMethodID := did.DIDURL{
		DID:      controller,
		Fragment: uuid.New().String(),
	}
	verificationMethodKey, err := m.keyStore.New(ctx, func(key crypt.PublicKey) (string, error) {
		return verificationMethodID.String(), nil
	})
	if err != nil {
		return nil, err
	}
	verificationMethod, err := did.NewVerificationMethod(verificationMethodID, ssi.JsonWebKey2020, controller, verificationMethodKey.Public())
	if err != nil {
		return nil, err
	}
	return verificationMethod, nil
}

// OnEvent just deletes the event.
func (m Manager) OnEvent(_ context.Context, event sql.DIDEventLog) {
	err := m.db.Delete(&event)
	if err != nil {
		// todo log
	}
}

// Loop requires no implementation for the DIDWeb method manager.
func (m Manager) Loop(_ context.Context) {
	// todo remove event from event log when found
	return
}

func buildDocument(newDID did.DID, verificationMethod did.VerificationMethod, keyTypes management.DIDKeyFlags) (did.Document, error) {
	document := did.Document{
		Context: []interface{}{
			ssi.MustParseURI(jsonld.Jws2020Context),
			did.DIDContextV1URI(),
		},
		ID:                 newDID,
		VerificationMethod: did.VerificationMethods([]*did.VerificationMethod{&verificationMethod}),
	}
	if keyTypes&management.KeyAgreementUsage != 0 {
		document.AddKeyAgreement(&verificationMethod)
	}
	if keyTypes&management.AssertionMethodUsage != 0 {
		document.AddAssertionMethod(&verificationMethod)
	}
	if keyTypes&management.AuthenticationUsage != 0 {
		document.AddAuthenticationMethod(&verificationMethod)
	}
	if keyTypes&management.CapabilityInvocationUsage != 0 {
		document.AddCapabilityInvocation(&verificationMethod)
	}
	if keyTypes&management.CapabilityDelegationUsage != 0 {
		document.AddCapabilityDelegation(&verificationMethod)
	}

	return document, nil
}
