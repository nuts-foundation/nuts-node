package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v2"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"path"
)

// leiaStore implements the issuer Store interface. It is a simple and fast json store.
// Note: It can not be used in a clustered setup.
type leiaStore struct {
	collection leia.Collection
}

// NewLeiaStore creates a new instance of leiaStore which implements the Store interface.
func NewLeiaStore(dataDir string) (Store, error) {
	dbPath := path.Join(dataDir, "vcr", "issued-credentials.db")
	store, err := leia.NewStore(dbPath, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create leiaStore: %w", err)
	}
	collection := store.Collection("issuedCredentials")
	newLeiaStore := &leiaStore{collection: collection}
	if err := newLeiaStore.createIndices(); err != nil {
		return nil, err
	}
	return newLeiaStore, nil
}

func (s leiaStore) StoreCredential(vc vc.VerifiableCredential) error {
	vcAsBytes, _ := json.Marshal(vc)
	doc := leia.DocumentFromBytes(vcAsBytes)
	return s.collection.Add([]leia.Document{doc})
}

func (s leiaStore) SearchCredential(jsonLDContext ssi.URI, credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	query := leia.New(leia.Eq("issuer", issuer.String())).
		And(leia.Eq("type", credentialType.String())).
		And(leia.Eq("@context", jsonLDContext.String()))

	if subject != nil {

		if subjectString := subject.String(); subjectString != "" {
			query = query.And(leia.Eq("credentialSubject.id", subjectString))
		}
	}

	docs, err := s.collection.Find(context.Background(), query)
	if err != nil {
		return nil, err
	}

	result := make([]vc.VerifiableCredential, len(docs))
	for i, doc := range docs {
		if err := json.Unmarshal(doc.Bytes(), &result[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s leiaStore) StoreRevocation(r credential.Revocation) error {
	//TODO implement me
	panic("implement me")
}

// createIndices creates the needed indices for the issued VC store
// It allows faster searching on context, type issuer and subject values.
func (s leiaStore) createIndices() error {
	index := leia.NewIndex("issuedVCs",
		leia.NewFieldIndexer("issuer"),
		leia.NewFieldIndexer("type"),
		leia.NewFieldIndexer("@context"),
		leia.NewFieldIndexer("credentialSubject.id"),
	)
	return s.collection.AddIndex(index)
}
