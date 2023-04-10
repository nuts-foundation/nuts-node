package issuer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/oidc4vci"
	"net/http"
	"sync"
)

type OIDCIssuer interface {
	ProviderMetadata() oidc4vci.ProviderMetadata
	RequestAccessToken(ctx context.Context, preAuthorizedCode string) (string, error)

	Metadata() oidc4vci.CredentialIssuerMetadata
	Offer(ctx context.Context, credential vc.VerifiableCredential, walletURL string) error
	GetCredential(ctx context.Context, accessToken string) (vc.VerifiableCredential, error)
}

// NewOIDCIssuer creates a new Issuer instance. The identifier is the Credential Issuer Identifier, e.g. https://example.com/issuer/
func NewOIDCIssuer(identifier string) OIDCIssuer {
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

func (i *memoryIssuer) Metadata() oidc4vci.CredentialIssuerMetadata {
	return oidc4vci.CredentialIssuerMetadata{
		CredentialIssuer:     i.identifier,
		CredentialEndpoint:   i.identifier + "/issuer/oidc4vci/credential",
		CredentialsSupported: []map[string]interface{}{{"NutsAuthorizationCredential": map[string]interface{}{}}},
	}
}

func (i *memoryIssuer) ProviderMetadata() oidc4vci.ProviderMetadata {
	return oidc4vci.ProviderMetadata{
		Issuer:        i.identifier,
		TokenEndpoint: i.identifier + "/oidc/token",
	}
}

func (i *memoryIssuer) RequestAccessToken(ctx context.Context, preAuthorizedCode string) (string, error) {
	i.mux.Lock()
	defer i.mux.Unlock()
	_, ok := i.state[preAuthorizedCode]
	if !ok {
		audit.Log(ctx, log.Logger(), audit.InvalidOAuthTokenEvent).
			Info("Client tried requesting access token (for OIDC4VCI) with unknown OAuth2 pre-authorized code")
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

	// TODO: Support TLS
	//       See https://github.com/nuts-foundation/nuts-node/issues/2032
	client, err := oidc4vci.NewWalletClient(ctx, &http.Client{}, clientMetadataURL)
	if err != nil {
		return err
	}

	offer := oidc4vci.CredentialOffer{
		CredentialIssuer: i.identifier,
		Credentials: []map[string]interface{}{{
			"format": "VerifiableCredentialJSONLDFormat",
			"credential_definition": map[string]interface{}{
				"@context": credential.Context,
				"types":    credential.Type,
			},
		}},
		Grants: []map[string]interface{}{
			{
				oidc4vci.PreAuthorizedCodeGrant: map[string]interface{}{
					"pre-authorized_code": preAuthorizedCode,
				},
			},
		},
	}

	err = client.OfferCredential(ctx, offer)
	if err != nil {
		return fmt.Errorf("unable to offer credential (url=%s): %w", client.Metadata().CredentialOfferEndpoint, err)
	}
	return nil
}

func (i *memoryIssuer) GetCredential(ctx context.Context, accessToken string) (vc.VerifiableCredential, error) {
	i.mux.Lock()
	defer i.mux.Unlock()
	// TODO: Verify requested format and credential definition
	//       See https://github.com/nuts-foundation/nuts-node/issues/2037
	// TODO: Verify Proof-of-Possession of private key material
	//       See https://github.com/nuts-foundation/nuts-node/issues/2036
	preAuthorizedCode, ok := i.accessTokens[accessToken]
	if !ok {
		audit.Log(ctx, log.Logger(), audit.InvalidOAuthTokenEvent).
			Info("Client tried retrieving credential over OIDC4VCI with unknown OAuth2 access token")
		return vc.VerifiableCredential{}, errors.New("invalid access token")
	}
	credential, _ := i.state[preAuthorizedCode]
	subjectDID, _ := getSubjectDID(credential)
	// Important: since we (for now) create the VC even before the wallet requests it, we don't know if every VC is actually retrieved by the wallet.
	//            This is a temporary shortcut, since changing that requires a lot of refactoring.
	//            To make actually retrieved VC traceable, we log it to the audit log.
	audit.Log(ctx, log.Logger(), audit.VerifiableCredentialRetrievedEvent).
		WithField(core.LogFieldCredentialID, credential.ID).
		WithField(core.LogFieldCredentialIssuer, credential.Issuer.String()).
		WithField(core.LogFieldCredentialSubject, subjectDID).
		Infof("VC retrieved by wallet over OIDC4VCI")
	// TODO: this is probably not correct, I think I read in the RFC that the VC should be retrievable multiple times
	//       See https://github.com/nuts-foundation/nuts-node/issues/2031
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
	// TODO: Replace with something securer?
	//		 See https://github.com/nuts-foundation/nuts-node/issues/2030
	buf := make([]byte, 64)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(buf)
}
