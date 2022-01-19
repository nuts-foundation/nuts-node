package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"time"
)

// NewIssuer creates a new issuer which implements the Issuer interface.
func NewIssuer(store Store, publisher Publisher, docResolver vdr.DocResolver, keyStore crypto.KeyStore) Issuer {
	resolver := vdrKeyResolver{docResolver: docResolver, keyResolver: keyStore}
	return issuer{
		store:       store,
		Publisher:   publisher,
		keyResolver: resolver,
	}
}

type issuer struct {
	store       Store
	Publisher   Publisher
	keyResolver keyResolver
}

// Issue creates a new credential, signs, stores and publishes it to the network.
func (i issuer) Issue(credentialOptions vc.VerifiableCredential, publish, public bool) (*vc.VerifiableCredential, error) {
	createdVC, err := i.buildVC(credentialOptions)
	if err != nil {
		return nil, err
	}

	validator, _ := credential.FindValidatorAndBuilder(*createdVC)
	if err := validator.Validate(*createdVC); err != nil {
		return nil, err
	}

	// TODO: Store credential in the store
	if err = i.store.StoreCredential(*createdVC, nil); err != nil {
		return nil, err
	}

	if publish {
		if err := i.Publisher.PublishCredential(*createdVC, public); err != nil {
			return nil, err
		}
	}
	return createdVC, nil
}

func (i issuer) buildVC(credentialOptions vc.VerifiableCredential) (*vc.VerifiableCredential, error) {
	if len(credentialOptions.Type) != 1 {
		return nil, errors.New("can only issue credential with 1 type")
	}

	// find issuer
	issuer, err := did.ParseDID(credentialOptions.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}

	credentialID, _ := ssi.ParseURI(fmt.Sprintf("%s#%s", issuer.String(), uuid.New().String()))
	unsignedCredential := vc.VerifiableCredential{
		Context:           append(credentialOptions.Context, vc.VCContextV1URI()),
		ID:                credentialID,
		Type:              credentialOptions.Type,
		CredentialSubject: credentialOptions.CredentialSubject,
		Issuer:            credentialOptions.Issuer,
		ExpirationDate:    credentialOptions.ExpirationDate,
		IssuanceDate:      time.Now(),
	}

	defaultType := vc.VerifiableCredentialTypeV1URI()
	if !unsignedCredential.IsType(defaultType) {
		unsignedCredential.Type = append(unsignedCredential.Type, defaultType)
	}

	key, err := i.keyResolver.ResolveAssertionKey(*issuer)
	if err != nil {
		return nil, fmt.Errorf("could not resolve kid: %w", err)
	}

	credentialAsMap := map[string]interface{}{}
	b, _ := json.Marshal(unsignedCredential)
	_ = json.Unmarshal(b, &credentialAsMap)

	signingResult, err := proof.LegacyLDProof{}.Sign(credentialAsMap, signature.LegacyNutsSuite{}, key)
	if err != nil {
		return nil, err
	}

	signingResultAsMap, ok := signingResult.(map[string]interface{})
	if !ok {
		return nil, errors.New("unable to cast signing result to interface map")
	}
	b, _ = json.Marshal(signingResultAsMap)
	signedCredential := &vc.VerifiableCredential{}
	json.Unmarshal(b, signedCredential)

	return signedCredential, nil
}

func (i issuer) Revoke(credentialID ssi.URI) error {
	//TODO implement me
	panic("implement me")
}

func (i issuer) CredentialResolver() StoreResolver {
	return i.store
}
