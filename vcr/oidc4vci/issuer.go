package oidc4vci

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/api/oidc4vci_v0/types"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"sync"
)

type Issuer interface {
	ProviderMetadata() types.OIDCProviderMetadata
	RequestAccessToken(preAuthorizedCode string) (string, error)

	Metadata() types.CredentialIssuerMetadata
	Offer(ctx context.Context, credential vc.VerifiableCredential, walletURL string) error
	GetCredential(accessToken string) (vc.VerifiableCredential, error)
}

// NewIssuer creates a new Issuer instance. The identifier is the Credential Issuer Identifier, e.g. https://example.com/issuer/
func NewIssuer(identifier string) Issuer {
	return &memoryIssuer{
		identifier:   identifier,
		state:        make(map[string]vc.VerifiableCredential),
		accessTokens: make(map[string]string),
		mux:          &sync.Mutex{},
	}
}

type memoryIssuer struct {
	identifier string
	// state maps a pre-authorized code to a Verifiable Credential
	state map[string]vc.VerifiableCredential
	// accessToken maps an access token to a pre-authorized code
	accessTokens map[string]string
	mux          *sync.Mutex
}

func (i *memoryIssuer) Metadata() types.CredentialIssuerMetadata {
	return types.CredentialIssuerMetadata{
		CredentialIssuer:     i.identifier,
		CredentialEndpoint:   i.identifier + "/issuer/oidc4vci/credential",
		CredentialsSupported: []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}},
	}
}

func (i *memoryIssuer) ProviderMetadata() types.OIDCProviderMetadata {
	return types.OIDCProviderMetadata{
		Issuer:        i.identifier,
		TokenEndpoint: i.identifier + "/oidc/token",
	}
}

func (i *memoryIssuer) RequestAccessToken(preAuthorizedCode string) (string, error) {
	i.mux.Lock()
	defer i.mux.Unlock()
	_, ok := i.state[preAuthorizedCode]
	if !ok {
		return "", errors.New("unknown pre-authorized code")
	}
	accessToken := generateCode()
	i.accessTokens[accessToken] = preAuthorizedCode
	return accessToken, nil
}

func (i *memoryIssuer) Offer(ctx context.Context, credential vc.VerifiableCredential, clientMetadataURL string) error {
	i.mux.Lock()
	preAuthorizedCode := generateCode()
	i.state[preAuthorizedCode] = credential
	i.mux.Unlock()

	subject, err := getSubjectDID(credential)
	if err != nil {
		return err
	}
	log.Logger().Infof("Publishing credential for subject %s using OIDC4VCI", subject)

	// TODO: Lookup Credential Wallet Client Metadata. For now, we use the local node

	client, err := NewHolderClient(clientMetadataURL)
	if err != nil {
		return err
	}

	// Lookup Credential Issuer Identifier in VC issuer's DID Document,
	// this is sent to the wallet in the Credential Offer, so the wallet can resolve the Credential Issuer Metadata
	// (by adding /.well-known/.... to the URL). For now, short circuit this because we have 1 node in the prototype.
	offer := types.CredentialOffer{
		CredentialIssuer: i.identifier,
		Credentials: []map[string]interface{}{{
			"format": "ldp_vc",
			"credential_definition": map[string]interface{}{
				"@context": credential.Context,
				"types":    credential.Type,
			},
		}},
		Grants: map[string]interface{}{
			types.PreAuthorizedCodeGrant: map[string]interface{}{
				"pre-authorized_code": preAuthorizedCode,
			},
		},
	}

	err = client.OfferCredential(ctx, offer)
	if err != nil {
		// TODO: Add client identifier/URL to error message?
		return fmt.Errorf("unable to offer credential: %w", err)
	}
	return nil
}

func (i *memoryIssuer) GetCredential(accessToken string) (vc.VerifiableCredential, error) {
	i.mux.Lock()
	defer i.mux.Unlock()
	preAuthorizedCode, ok := i.accessTokens[accessToken]
	if !ok {
		return vc.VerifiableCredential{}, errors.New("invalid access token")
	}
	credential, _ := i.state[preAuthorizedCode]
	// TODO (non-prototype): this is probably not correct, I think I read in the RFC that the VC should be retrievable multiple times
	delete(i.accessTokens, accessToken)
	delete(i.state, preAuthorizedCode)
	return credential, nil
}

func getSubjectDID(verifiableCredential vc.VerifiableCredential) (string, error) {
	type subjectType struct {
		ID string `json:"id"`
	}
	var subject []subjectType
	err := verifiableCredential.UnmarshalCredentialSubject(&subject)
	if err != nil {
		return "", fmt.Errorf("unable to unmarshal credential subject: %w", err)
	}
	if len(subject) == 0 {
		return "", errors.New("missing subject ID")
	}
	return subject[0].ID, err
}

func generateCode() string {
	buf := make([]byte, 64)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(buf)
}
