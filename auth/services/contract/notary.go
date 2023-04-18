/*
 * Nuts node
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package contract

import (
	"context"
	"errors"
	"fmt"

	"github.com/nuts-foundation/nuts-node/core"
	"reflect"
	"strings"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/dummy"
	"github.com/nuts-foundation/nuts-node/auth/services/irma"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned"
	"github.com/nuts-foundation/nuts-node/auth/services/uzi"
	"github.com/nuts-foundation/nuts-node/auth/services/x509"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/pki"
	pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	irmago "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

// ErrMissingOrganizationKey is used to indicate that this node has no private key of the indicated organization.
// This usually means that the organization is not managed by this node.
var ErrMissingOrganizationKey = errors.New("missing organization private key")

// ErrUnknownSigningMeans is used when the node does not now how to handle the indicated signing means
// todo move
var ErrUnknownSigningMeans = errors.New("unknown signing means")

// Config holds all the configuration params
// todo this doubles the pkg/Config?
type Config struct {
	AutoUpdateIrmaSchemas bool
	StrictMode            bool
	PublicURL             string
	IrmaConfigPath        string
	IrmaSchemeManager     string
	ContractValidators    []string
	ContractValidity      time.Duration
}

func (c Config) hasContractValidator(cv string) bool {
	for _, curr := range c.ContractValidators {
		if strings.EqualFold(cv, curr) {
			return true
		}
	}

	return false
}

type notary struct {
	config          Config
	jsonldManager   jsonld.JSONLD
	keyResolver     types.KeyResolver
	privateKeyStore crypto.KeyStore
	verifiers       map[string]contract.VPVerifier
	signers         map[string]contract.Signer
	vcr             vcr.VCR
	uziCrlValidator pki.Validator
}

var timeNow = time.Now

// NewNotary accepts the registry and crypto Nuts engines and returns a ContractNotary
func NewNotary(config Config, vcr vcr.VCR, keyResolver types.KeyResolver, keyStore crypto.KeyStore, jsonldManager jsonld.JSONLD) services.ContractNotary {
	return &notary{
		config:          config,
		jsonldManager:   jsonldManager,
		vcr:             vcr,
		keyResolver:     keyResolver,
		privateKeyStore: keyStore,
	}
}

// DrawUpContract accepts a template and fills in the Party, validFrom time and its duration.
// If validFrom is zero, the current time is used.
// If the duration is 0 than the default duration is used.
func (n *notary) DrawUpContract(ctx context.Context, template contract.Template, orgID did.DID, validFrom time.Time, validDuration time.Duration, organizationCredential *vc.VerifiableCredential) (*contract.Contract, error) {
	// Test if the org in managed by this node:
	signingKeyID, err := n.keyResolver.ResolveSigningKeyID(orgID, &validFrom)
	if errors.Is(err, types.ErrNotFound) {
		return nil, services.NewInvalidContractRequestError("no valid organization credential at provided validFrom date")
	} else if err != nil {
		return nil, fmt.Errorf("could not draw up contract: %w", err)
	}

	if !n.privateKeyStore.Exists(ctx, signingKeyID) {
		return nil, services.NewInvalidContractRequestError(fmt.Errorf("organization is not managed by this node: %w", ErrMissingOrganizationKey))
	}

	var orgName, orgCity string
	if organizationCredential != nil {
		orgName, orgCity, err = n.attributesFromOrganizationCredential(*organizationCredential)
	} else {
		orgName, orgCity, err = n.findVC(orgID)
	}
	if err != nil {
		return nil, err
	}

	// name and city must exist since we queried it
	contractAttrs := map[string]string{
		contract.LegalEntityAttr:     orgName,
		contract.LegalEntityCityAttr: orgCity,
	}

	if validDuration == 0 {
		validDuration = n.config.ContractValidity
	}

	if validFrom.IsZero() {
		validFrom = timeNow()
	}

	drawnUpContract, err := template.Render(contractAttrs, validFrom, validDuration)
	if err != nil {
		return nil, fmt.Errorf("could not draw up contract: %w", err)
	}

	return drawnUpContract, nil
}

func (n *notary) Configure() (err error) {
	n.verifiers = map[string]contract.VPVerifier{}
	n.signers = map[string]contract.Signer{}

	cvMap := make(map[string]bool, len(n.config.ContractValidators))
	for _, cv := range n.config.ContractValidators {
		cvMap[cv] = true
	}

	if n.config.hasContractValidator("irma") {
		var (
			irmaConfig *irmago.Configuration
			irmaServer *irmaserver.Server
		)

		irmaServiceConfig := irma.Config{
			PublicURL:             n.config.PublicURL,
			IrmaConfigPath:        n.config.IrmaConfigPath,
			IrmaSchemeManager:     n.config.IrmaSchemeManager,
			AutoUpdateIrmaSchemas: n.config.AutoUpdateIrmaSchemas,
			// Deduce IRMA production mode from the nuts strict-mode
			Production: n.config.StrictMode,
		}

		if irmaServer, irmaConfig, err = n.configureIrma(irmaServiceConfig); err != nil {
			return
		}

		irmaSigner := irma.Signer{
			IrmaSessionHandler: &irma.DefaultIrmaSessionHandler{I: irmaServer},
			Signer:             n.privateKeyStore,
			IrmaServiceConfig:  irmaServiceConfig,
		}

		irmaVerifier := irma.Verifier{
			IrmaConfig: irmaConfig,
			Templates:  contract.StandardContractTemplates,
		}

		// todo config to VP types
		if _, ok := cvMap[irma.ContractFormat]; ok {
			n.verifiers[irma.VerifiablePresentationType] = irmaVerifier
			n.signers[irma.ContractFormat] = irmaSigner
		}
	}

	if _, ok := cvMap[dummy.ContractFormat]; ok && !n.config.StrictMode {
		d := dummy.Dummy{
			Sessions: map[string]string{},
			Status:   map[string]string{},
		}

		n.verifiers[dummy.VerifiablePresentationType] = d
		n.signers[dummy.ContractFormat] = d
	}

	if _, ok := cvMap[uzi.ContractFormat]; ok {
		truststore, err := x509.LoadUziTruststore(x509.UziAcceptation)
		if err != nil {
			return err
		}

		pkiCfg := pkiconfig.Config{
			MaxUpdateFailHours: 4,
		}

		n.uziCrlValidator, err = pki.NewValidator(pkiCfg, truststore.Certificates())
		if err != nil {
			return err
		}
		uziValidator, err := x509.NewUziValidator(truststore, &contract.StandardContractTemplates, n.uziCrlValidator)
		uziVerifier := uzi.Verifier{UziValidator: uziValidator}

		if err != nil {
			return fmt.Errorf("could not initiate uzi validator: %w", err)
		}

		n.verifiers[uzi.VerifiablePresentationType] = uziVerifier
	}

	if _, ok := cvMap[selfsigned.ContractFormat]; ok {
		es := selfsigned.NewSigner(n.vcr)
		ev := selfsigned.NewValidator(n.vcr, contract.StandardContractTemplates)

		n.verifiers[selfsigned.VerifiablePresentationType] = ev
		n.signers[selfsigned.ContractFormat] = es
	}

	return
}

func (n *notary) Start(ctx context.Context) {
	if n.uziCrlValidator != nil {
		n.uziCrlValidator.Start(ctx)
	}
}

func (n *notary) VerifyVP(vp vc.VerifiablePresentation, checkTime *time.Time) (contract.VPVerificationResult, error) {
	// remove default type
	vpTypes := make([]ssi.URI, len(vp.Type))
	i := 0
	for _, x := range vp.Type {
		if x != vc.VerifiablePresentationTypeV1URI() {
			vpTypes[i] = x
			i++
		}
	}
	vpTypes = vpTypes[:i]

	if len(vpTypes) != 1 {
		return nil, errors.New("unprocessable VerifiablePresentation, exactly 1 custom type is expected")
	}
	t := vpTypes[0]

	if _, ok := n.verifiers[t.String()]; !ok {
		return nil, fmt.Errorf("unknown VerifiablePresentation type: %s", t)
	}

	return n.verifiers[t.String()].VerifyVP(vp, checkTime)
}

func (n *notary) SigningSessionStatus(ctx context.Context, sessionID string) (contract.SigningSessionResult, error) {
	for _, signer := range n.signers {
		if r, err := signer.SigningSessionStatus(ctx, sessionID); !errors.Is(err, services.ErrSessionNotFound) {
			return r, err
		}
	}
	return nil, services.ErrSessionNotFound
}

func (n *notary) configureIrma(config irma.Config) (*irmaserver.Server, *irmago.Configuration, error) {
	irmaConfig, err := irma.GetIrmaConfig(config)
	if err != nil {
		return nil, nil, err
	}
	irmaServer, err := irma.GetIrmaServer(config, irmaConfig)
	if err != nil {
		return nil, nil, err
	}

	return irmaServer, irmaConfig, nil
}

func (n *notary) Routes(router core.EchoRouter) {
	for _, signer := range n.signers {
		if r, ok := signer.(core.Routable); ok {
			r.Routes(router)
		}
	}
}

// CreateSigningSession creates a session based on a contract. This allows the user to permit the application to
// use the Nuts Network in its name. By signing it with a cryptographic means other
// nodes in the network can verify the validity of the contract.
func (n *notary) CreateSigningSession(sessionRequest services.CreateSessionRequest) (contract.SessionPointer, error) {
	if sessionRequest.Message == "" {
		return nil, errors.New("can not sign an empty message")
	}

	// find correct signer
	signer, ok := n.signers[sessionRequest.SigningMeans]
	if !ok {
		return nil, ErrUnknownSigningMeans
	}

	// Get the contract by trying to parse the rawContractText
	c, err := contract.ParseContractString(sessionRequest.Message, contract.StandardContractTemplates)
	if err != nil {
		return nil, err
	}

	return signer.StartSigningSession(*c, sessionRequest.Params)
}

func (n *notary) findVC(orgID did.DID) (string, string, error) {
	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.CredentialSubjectPath, Value: orgID.String()},
		{IRIPath: jsonld.OrganizationNamePath, Type: vcr.NotNil},
		{IRIPath: jsonld.OrganizationCityPath, Type: vcr.NotNil},
	}

	result, err := n.vcr.Search(context.Background(), searchTerms, false, nil)
	if err != nil {
		return "", "", fmt.Errorf("could not find a credential: %w", err)
	}
	if len(result) == 0 {
		return "", "", services.NewInvalidContractRequestError(errors.New("could not find a NutsOrganizationCredential for this legalEntity issued by a trusted issuer"))
	}

	// Having multiple VCs with non-matching credentialSubjects for this DID is not supported.
	// If multiple non-matching VCs exist, a preferred VC must be passed to DrawUpContract.
	if len(result) > 1 {
		var credentialSubject interface{}
		for _, current := range result {
			if credentialSubject != nil && !reflect.DeepEqual(credentialSubject, current.CredentialSubject) {
				return "", "", services.NewInvalidContractRequestError(errors.New("found multiple non-matching VCs, which is not supported"))
			}
			credentialSubject = current.CredentialSubject
		}
	}

	return n.attributesFromOrganizationCredential(result[0])
}

func (n *notary) attributesFromOrganizationCredential(organizationCredential vc.VerifiableCredential) (string, string, error) {
	// expand
	reader := jsonld.Reader{
		DocumentLoader:           n.jsonldManager.DocumentLoader(),
		AllowUndefinedProperties: true,
	}
	document, err := reader.Read(organizationCredential)
	if err != nil {
		return "", "", fmt.Errorf("could not read VC: %w", err)
	}

	orgNames := document.ValueAt(jsonld.OrganizationNamePath)
	orgCities := document.ValueAt(jsonld.OrganizationCityPath)

	if len(orgNames) == 0 || len(orgCities) == 0 {
		return "", "", errors.New("verifiable credential does not contain an organization name and city")
	}

	return orgNames[0].String(), orgCities[0].String(), nil
}
