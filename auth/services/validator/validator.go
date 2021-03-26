/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package validator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/services/uzi"
	"github.com/nuts-foundation/nuts-node/auth/services/x509"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/nuts-node/auth/services/dummy"

	irmago "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/irma"
)

// Config holds all the configuration params
// todo this doubles the pkg/Config?
type Config struct {
	PublicURL             string
	IrmaConfigPath        string
	IrmaSchemeManager     string
	AutoUpdateIrmaSchemas bool
	ContractValidators    []string
	StrictMode            bool
}

func (c Config) hasContractValidator(cv string) bool {
	for _, curr := range c.ContractValidators {
		if strings.ToLower(cv) == strings.ToLower(curr) {
			return true
		}
	}
	return false
}

type service struct {
	config            Config
	irmaServiceConfig irma.ValidatorConfig
	irmaServer        *irmaserver.Server
	verifiers         map[contract.VPType]contract.VPVerifier
	signers           map[contract.SigningMeans]contract.Signer
	didResolver       types.Resolver
	privateKeyStore   crypto.PrivateKeyStore
}

// NewContractInstance accepts a Config and several Nuts engines and returns a new instance of services.ContractClient
func NewContractInstance(config Config, didResolver types.Resolver, privateKeyStore crypto.PrivateKeyStore) services.ContractClient {
	return &service{
		config:          config,
		didResolver:     didResolver,
		privateKeyStore: privateKeyStore,
	}
}

// Already a good candidate for removal
func (s *service) Configure() (err error) {
	s.verifiers = map[contract.VPType]contract.VPVerifier{}
	s.signers = map[contract.SigningMeans]contract.Signer{}

	cvMap := make(map[contract.SigningMeans]bool, len(s.config.ContractValidators))
	for _, cv := range s.config.ContractValidators {
		cvMap[contract.SigningMeans(cv)] = true
	}

	fmt.Printf("Validators: %v\n", s.config.ContractValidators)
	if s.config.hasContractValidator("irma") {
		var (
			irmaConfig *irmago.Configuration
			irmaServer *irmaserver.Server
		)

		if irmaServer, irmaConfig, err = s.configureIrma(s.config); err != nil {
			return
		}

		irmaService := irma.Service{
			IrmaSessionHandler: &irma.DefaultIrmaSessionHandler{I: irmaServer},
			IrmaConfig:         irmaConfig,
			DIDResolver:        s.didResolver,
			Signer:             s.privateKeyStore,
			IrmaServiceConfig:  s.irmaServiceConfig,
			ContractTemplates:  contract.StandardContractTemplates,
		}

		// todo config to VP types
		if _, ok := cvMap[irma.ContractFormat]; ok {
			s.verifiers[irma.VerifiablePresentationType] = irmaService
			s.signers[irma.ContractFormat] = irmaService
		}
	}

	if _, ok := cvMap[dummy.ContractFormat]; ok && !s.config.StrictMode {
		d := dummy.Dummy{
			Sessions: map[string]string{},
			Status:   map[string]string{},
		}
		s.verifiers[dummy.VerifiablePresentationType] = d
		s.signers[dummy.ContractFormat] = d
	}

	if _, ok := cvMap[uzi.ContractFormat]; ok {
		crlGetter := x509.NewCachedHTTPCRLGetter()
		uziValidator, err := x509.NewUziValidator(x509.UziAcceptation, &contract.StandardContractTemplates, crlGetter)
		uziVerifier := uzi.Verifier{UziValidator: uziValidator}

		if err != nil {
			return fmt.Errorf("could not initiate uzi validator: %w", err)
		}

		s.verifiers[uzi.VerifiablePresentationType] = uziVerifier
	}
	return
}

func (s *service) VerifyVP(rawVerifiablePresentation []byte, checkTime *time.Time) (*contract.VPVerificationResult, error) {
	vp := contract.BaseVerifiablePresentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &vp); err != nil {
		return nil, fmt.Errorf("unable to verifyVP: %w", err)
	}

	// remove default type
	types := vp.Type
	n := 0
	for _, x := range types {
		if x != contract.VerifiablePresentationType {
			types[n] = x
			n++
		}
	}
	types = types[:n]

	if len(types) != 1 {
		return nil, errors.New("unprocessable VerifiablePresentation, exactly 1 custom type is expected")
	}
	t := types[0]

	if _, ok := s.verifiers[t]; !ok {
		return nil, fmt.Errorf("unknown VerifiablePresentation type: %s", t)
	}

	return s.verifiers[t].VerifyVP(rawVerifiablePresentation, checkTime)
}

func (s *service) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	for _, signer := range s.signers {
		if r, err := signer.SigningSessionStatus(sessionID); !errors.Is(err, services.ErrSessionNotFound) {
			return r, err
		}
	}
	return nil, services.ErrSessionNotFound
}

func (s *service) configureIrma(config Config) (irmaServer *irmaserver.Server, irmaConfig *irmago.Configuration, err error) {
	s.irmaServiceConfig = irma.ValidatorConfig{
		PublicURL:             config.PublicURL,
		IrmaConfigPath:        config.IrmaConfigPath,
		IrmaSchemeManager:     config.IrmaSchemeManager,
		AutoUpdateIrmaSchemas: config.AutoUpdateIrmaSchemas,
	}
	if irmaConfig, err = irma.GetIrmaConfig(s.irmaServiceConfig); err != nil {
		return
	}
	if irmaServer, err = irma.GetIrmaServer(s.irmaServiceConfig, irmaConfig); err != nil {
		return
	}
	s.irmaServer = irmaServer
	return
}

// HandlerFunc returns the Irma server handler func
func (s *service) HandlerFunc() http.HandlerFunc {
	return s.irmaServer.HandlerFunc()
}

// ErrMissingOrganizationKey is used to indicate that this node has no private key of the indicated organization.
// This usually means that the organization is not managed by this node.
var ErrMissingOrganizationKey = errors.New("missing organization private key")

// ErrUnknownSigningMeans is used when the node does not now how to handle the indicated signing means
// todo move
var ErrUnknownSigningMeans = errors.New("unknown signing means")

// CreateSigningSession creates a session based on a contract. This allows the user to permit the application to
// use the Nuts Network in its name. By signing it with a cryptographic means other
// nodes in the network can verify the validity of the contract.
func (s *service) CreateSigningSession(sessionRequest services.CreateSessionRequest) (contract.SessionPointer, error) {
	if sessionRequest.Message == "" {
		return nil, errors.New("can not sign an empty message")
	}
	// find correct signer
	signer, ok := s.signers[sessionRequest.SigningMeans]
	if !ok {
		return nil, ErrUnknownSigningMeans
	}
	return signer.StartSigningSession(sessionRequest.Message)
}
