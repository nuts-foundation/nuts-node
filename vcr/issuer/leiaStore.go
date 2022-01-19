package issuer

import (
	"context"
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v2"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"path"
	"time"
)

type leiaStore struct {
	collection leia.Collection
}

// NewLeiaStore creates a new instance of leiaStore which implements the Store interface.
func NewLeiaStore(dataDir string) (Store, error) {
	dbPath := path.Join(dataDir, "vcr", "issued-credentials.db")
	store, err := leia.NewStore(dbPath, false)
	if err != nil {
		return nil, err
	}
	collection := store.Collection("issuedCredentials")
	return leiaStore{collection: collection}, nil
}

func (s leiaStore) StoreCredential(vc vc.VerifiableCredential, validAt *time.Time) error {
	vcAsBytes, _ := json.Marshal(vc)
	doc := leia.DocumentFromBytes(vcAsBytes)
	return s.collection.Add([]leia.Document{doc})
}

func (s leiaStore) SearchCredential(jsonLDContext ssi.URI, credentialType string, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	query := leia.New(leia.Eq("issuer", issuer.String())).
		And(leia.Eq("type", credentialType))
	if subjectString := subject.String(); subjectString != "" {
		query = query.And(leia.Eq("credentialSubject.id", subjectString))
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
