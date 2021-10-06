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

package irma

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/nuts-node/auth/services"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"

	irmaserver2 "github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/nuts-foundation/nuts-node/auth/contract"

	irma "github.com/privacybydesign/irmago"
	irmaserver "github.com/privacybydesign/irmago/server"
)

// VerifiablePresentationType is the irma verifiable presentation type
const VerifiablePresentationType = contract.VPType("NutsIrmaPresentation")

// ContractFormat holds the readable identifier of this signing means.
const ContractFormat = contract.SigningMeans("irma")

// ErrLegalEntityNotProvided indicates that the legalEntity is missing
var ErrLegalEntityNotProvided = errors.New("legalEntity not provided")

func init() {
	jwt.RegisterCustomField("sig", "")
}

// Service validates contracts using the IRMA logic.
type Service struct {
	IrmaSessionHandler SessionHandler
	IrmaConfig         *irma.Configuration
	IrmaServiceConfig  ValidatorConfig
	Signer             nutsCrypto.JWTSigner
	ContractTemplates  contract.TemplateStore
	StrictMode         bool
}

// ValidatorConfig holds the configuration for the irma validator.
type ValidatorConfig struct {
	// PublicURL is used for discovery for the IRMA app.
	PublicURL string
	// Where to find the IrmaConfig files including the schemas
	IrmaConfigPath string
	// Which scheme manager to use
	IrmaSchemeManager string
	// Auto update the schemas every x minutes or not?
	AutoUpdateIrmaSchemas bool
}

// VerifiablePresentation is a specific proof for irma signatures
type VerifiablePresentation struct {
	contract.VerifiablePresentationBase
	Proof VPProof `json:"proof"`
}

// VPProof is a specific IrmaProof for the specific VerifiablePresentation
type VPProof struct {
	contract.Proof
	ProofValue string `json:"proofValue"`
}

type irmaVPVerificationResult struct {
	validity            contract.State
	vpType              contract.VPType
	disclosedAttributes map[string]string
	contractAttributes  map[string]string
}

func (I irmaVPVerificationResult) Validity() contract.State {
	return I.validity
}

func (I irmaVPVerificationResult) VPType() contract.VPType {
	return I.vpType
}

func (I irmaVPVerificationResult) DisclosedAttribute(key string) string {
	var v string
	switch key {
	case services.FamilyNameTokenClaim:
		v = I.disclosedAttributes["gemeente.personalData.familyname"]
	case services.PrefixTokenClaim:
		v = I.disclosedAttributes["gemeente.personalData.prefix"]
	case services.InitialsTokenClaim:
		v = I.disclosedAttributes["gemeente.personalData.initials"]
	case services.EmailTokenClaim:
		v = I.disclosedAttributes["sidn-pbdf.email.email"]
	case services.EidasIALClaim:
		v = I.disclosedAttributes["gemeente.personalData.digidlevel"]
	}
	return v
}

func (I irmaVPVerificationResult) ContractAttribute(key string) string {
	return I.contractAttributes[key]
}

func (I irmaVPVerificationResult) DisclosedAttributes() map[string]string {
	return I.disclosedAttributes
}

func (I irmaVPVerificationResult) ContractAttributes() map[string]string {
	return I.contractAttributes
}

// VerifyVP expects the given raw VerifiablePresentation to be of the correct type
// todo: type check?
func (v Service) VerifyVP(rawVerifiablePresentation []byte, checkTime *time.Time) (contract.VPVerificationResult, error) {
	// Extract the Irma message
	vp := VerifiablePresentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &vp); err != nil {
		return nil, fmt.Errorf("could not verify VP: %w", err)
	}

	// Create the irma contract validator
	contractValidator := contractVerifier{irmaConfig: v.IrmaConfig, validContracts: v.ContractTemplates, strictMode: v.StrictMode}
	signedContract, err := contractValidator.Parse(vp.Proof.ProofValue)
	if err != nil {
		return nil, err
	}

	cvr, err := contractValidator.verifyAll(signedContract.(*SignedIrmaContract), checkTime)
	if err != nil {
		return nil, err
	}

	signerAttributes, err := signedContract.SignerAttributes()
	if err != nil {
		return nil, fmt.Errorf("could not verify vp: could not get signer attributes: %w", err)
	}

	return irmaVPVerificationResult{
		validity:            contract.State(cvr.ValidationResult),
		vpType:              contract.VPType(cvr.ContractFormat),
		disclosedAttributes: signerAttributes,
		contractAttributes:  signedContract.Contract().Params,
	}, nil
}

// SessionHandler is an abstraction for the Irma Server, mainly for enabling better testing
type SessionHandler interface {
	GetSessionResult(token string) *irmaserver.SessionResult
	StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, irma.RequestorToken, *irma.FrontendSessionRequest, error)
}

// Compile time check if the DefaultIrmaSessionHandler implements the SessionHandler interface
var _ SessionHandler = (*DefaultIrmaSessionHandler)(nil)

// DefaultIrmaSessionHandler is a wrapper for the Irma Server
// It implements the SessionHandler interface
type DefaultIrmaSessionHandler struct {
	I *irmaserver2.Server
}

// GetSessionResult forwards to Irma Server instance
func (d *DefaultIrmaSessionHandler) GetSessionResult(token string) *irmaserver.SessionResult {
	return d.I.GetSessionResult(irma.RequestorToken(token))
}

// StartSession forwards to Irma Server instance
func (d *DefaultIrmaSessionHandler) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, irma.RequestorToken, *irma.FrontendSessionRequest, error) {
	return d.I.StartSession(request, handler)
}
