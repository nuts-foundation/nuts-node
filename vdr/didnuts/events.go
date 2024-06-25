package didnuts

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/util"
	"github.com/nuts-foundation/nuts-node/vdr/events"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/nuts-foundation/nuts-node/vdr/sql"
	"gorm.io/gorm"
)

var _ events.MethodManager = (*Manager)(nil)

func (m Manager) GenerateDocument(ctx context.Context, _ string, keyFlags management.DIDKeyFlags) (*did.Document, error) {
	// First, generate a new keyPair with the correct kid
	// Currently, always keep the key in the keystore. This allows us to change the transaction format and regenerate transactions at a later moment.
	// Relevant issue:
	// https://github.com/nuts-foundation/nuts-node/issues/1947
	key, err := m.KeyStore.New(ctx, didKIDNamingFunc)
	if err != nil {
		return nil, err
	}

	keyID, err := did.ParseDIDURL(key.KID())
	if err != nil {
		return nil, err
	}

	// Create the bare document. The Document DID will be the keyIDStr without the fragment.
	didID, _ := resolver.GetDIDFromURL(key.KID())
	doc := CreateDocument()
	doc.ID = didID

	var verificationMethod *did.VerificationMethod

	// Add VerificationMethod using generated key
	verificationMethod, err = did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key.Public())
	if err != nil {
		return nil, err
	}

	applyKeyUsage(&doc, verificationMethod, keyFlags)
	return &doc, nil
}

func (m Manager) GenerateVerificationMethod(ctx context.Context, controller did.DID) (*did.VerificationMethod, error) {
	return CreateNewVerificationMethodForDID(ctx, controller, m.KeyStore)
}

// OnEvent requires no implementation for the DIDWeb method manager.
func (m Manager) OnEvent(ctx context.Context, event sql.DIDEventLog) {
	switch event.EventType {
	case events.DIDEventCreated:
		m.onCreate(ctx, event)
	case events.DIDEventDeactivated:
		m.onDeactivate(ctx, event)
	case events.DIDEventUpdated:
		m.onUpdate(ctx, event)
	default:
		// todo log something
	}
}

func (m Manager) onCreate(ctx context.Context, event sql.DIDEventLog) {
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		didDocument, signingVerificationMethod, err := reconstructDocument(event.DIDDocumentVersion)
		if err != nil {
			return err
		}
		// publish
		payload, err := json.Marshal(didDocument)
		if err != nil {
			return err
		}

		// extract the transaction refs from the controller metadata
		refs := make([]hash.SHA256Hash, 0)
		key := cryptoKey{vm: signingVerificationMethod}
		networkTx := network.TransactionTemplate(DIDDocumentType, payload, key).WithAttachKey().WithAdditionalPrevs(refs)
		_, err = m.NetworkClient.CreateTransaction(ctx, networkTx)
		if err != nil {
			return fmt.Errorf("could not publish DID document on the network: %w", err)
		}

		// remove the event from the log
		return tx.Delete(&event).Error
	})
	if err != nil {
		//log // todo
	}
}

func (m Manager) onUpdate(ctx context.Context, event sql.DIDEventLog) {
	id := event.DID()
	resolverMetadata := &resolver.ResolveMetadata{
		AllowDeactivated: true,
	}

	currentDIDDocument, currentMeta, err := m.Resolver.Resolve(id, resolverMetadata)
	if err != nil {
		// todo log
	}
	if resolver.IsDeactivated(*currentDIDDocument) {
		// todo delete db entry and log debug
	}
	next, _, err := reconstructDocument(event.DIDDocumentVersion)
	if err != nil {
		// todo log
	}

	// #1530: add nuts and JWS context if not present
	next = withJSONLDContext(next, NutsDIDContextV1URI())
	next = withJSONLDContext(next, JWS2020ContextV1URI())

	// Validate document. No more changes should be made to the document after this point.
	didResolver := resolver.DIDResolverRouter{}
	serviceResolver := resolver.DIDServiceResolver{Resolver: &didResolver}
	if err = ManagedDocumentValidator(serviceResolver).Validate(next); err != nil {
		// log
	}

	payload, err := json.Marshal(next)
	if err != nil {
		// log
	}

	controller, key, err := m.resolveControllerWithKey(ctx, *currentDIDDocument)
	if err != nil {
		// log
	}

	// for the metadata
	_, controllerMeta, err := didResolver.Resolve(controller.ID, nil)
	if err != nil {
		// log
	}

	// a DIDDocument update must point to its previous version, current heads and the controller TX (for signing key transaction ordering)
	previousTransactions := append(currentMeta.SourceTransactions, controllerMeta.SourceTransactions...)

	tx := network.TransactionTemplate(DIDDocumentType, payload, key).WithAdditionalPrevs(previousTransactions)
	_, err = m.NetworkClient.CreateTransaction(ctx, tx)
	if err != nil {
		// log
		if errors.Is(err, nutsCrypto.ErrPrivateKeyNotFound) {
			// log and remove entry
		}
	}

	err = m.DB.Transaction(func(tx *gorm.DB) error {
		// remove the event from the log
		return tx.Delete(&event).Error
	})
	if err != nil {
		//log // todo
	}
}

func (m Manager) onDeactivate(ctx context.Context, event sql.DIDEventLog) {
	err := m.DB.Transaction(func(tx *gorm.DB) error {
		err := m.Deactivate(ctx, event.DID())
		if err != nil {
			return fmt.Errorf("could not deactivate DID document on the network: %w", err)
		}

		// remove the event from the log
		return tx.Delete(&event).Error
	})
	if err != nil {
		//log // todo
	}
}

type cryptoKey struct {
	vm did.VerificationMethod
}

func (c cryptoKey) KID() string {
	return c.vm.ID.String()
}

func (c cryptoKey) Public() crypto.PublicKey {
	pk, _ := c.vm.PublicKey() // todo
	return pk
}

// Loop requires no implementation for the DIDWeb method manager.
func (m Manager) Loop(_ context.Context) {
	return
}

func reconstructDocument(sqlDocumentVersion sql.DIDDocument) (did.Document, did.VerificationMethod, error) {
	id, _ := did.ParseDID(sqlDocumentVersion.DID.ID)
	document := did.Document{
		// todo context in db
		Context: []interface{}{
			ssi.MustParseURI(jsonld.Jws2020Context),
			did.DIDContextV1URI(),
		},
		ID: *id,
	}

	// add services
	for _, service := range sqlDocumentVersion.Services {
		// parse as did.Service
		var s did.Service
		err := json.Unmarshal(service.Data, &s)
		if err != nil {
			return did.Document{}, did.VerificationMethod{}, err
		}
		document.Service = append(document.Service, s)
	}

	// select a verification method to use as key
	// add verification methods
	var signingMethod *did.VerificationMethod
	for _, vm := range sqlDocumentVersion.VerificationMethods {
		// parse as did.VerificationMethod
		var v did.VerificationMethod
		err := json.Unmarshal(vm.Data, &v)
		if err != nil {
			return did.Document{}, did.VerificationMethod{}, err
		}
		if vm.KeyTypes&sql.VerificationMethodKeyType(management.KeyAgreementUsage) != 0 {
			document.AddKeyAgreement(&v)
		}
		if vm.KeyTypes&sql.VerificationMethodKeyType(management.AssertionMethodUsage) != 0 {
			document.AddAssertionMethod(&v)
		}
		if vm.KeyTypes&sql.VerificationMethodKeyType(management.AuthenticationUsage) != 0 {
			document.AddAuthenticationMethod(&v)
		}
		if vm.KeyTypes&sql.VerificationMethodKeyType(management.CapabilityInvocationUsage) != 0 {
			if signingMethod == nil {
				signingMethod = &v
			}
			document.AddCapabilityInvocation(&v)
		}
		if vm.KeyTypes&sql.VerificationMethodKeyType(management.CapabilityDelegationUsage) != 0 {
			document.AddCapabilityDelegation(&v)
		}
	}

	// todo AlsoKnownAs

	return document, *signingMethod, nil
}

func withJSONLDContext(document did.Document, ctx ssi.URI) did.Document {
	contextPresent := false

	for _, c := range document.Context {
		if util.LDContextToString(c) == ctx.String() {
			contextPresent = true
		}
	}

	if !contextPresent {
		document.Context = append(document.Context, ctx)
	}
	return document
}

func (m Manager) resolveControllerWithKey(ctx context.Context, doc did.Document) (did.Document, nutsCrypto.Key, error) {
	controllers, err := ResolveControllers(m.Store, doc, nil)
	if err != nil {
		return did.Document{}, nil, fmt.Errorf("error while finding controllers for document: %w", err)
	}
	if len(controllers) == 0 {
		return did.Document{}, nil, fmt.Errorf("could not find any controllers for document")
	}

	var key nutsCrypto.Key
	for _, c := range controllers {
		for _, cik := range c.CapabilityInvocation {
			key, err = m.KeyStore.Resolve(ctx, cik.ID.String())
			if err == nil {
				return c, key, nil
			}
		}
	}

	if errors.Is(err, nutsCrypto.ErrPrivateKeyNotFound) {
		// log
	}

	return did.Document{}, nil, fmt.Errorf("could not find capabilityInvocation key for updating the DID document: %w", err)
}
