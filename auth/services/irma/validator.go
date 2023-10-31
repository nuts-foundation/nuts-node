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
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"

	irma "github.com/privacybydesign/irmago"
)

// VerifiablePresentationType is the irma verifiable presentation type
const VerifiablePresentationType = "NutsIrmaPresentation"

// ContractFormat holds the readable identifier of this signing means.
const ContractFormat = "irma"

// ErrLegalEntityNotProvided indicates that the legalEntity is missing
var ErrLegalEntityNotProvided = errors.New("legalEntity not provided")

func init() {
	jwt.RegisterCustomField("sig", "")
}

// VPProof is a specific IrmaProof for the specific VerifiablePresentation
type VPProof struct {
	Type       string `json:"type"`
	ProofValue string `json:"proofValue"`
}

type Verifier struct {
	IrmaConfig *irma.Configuration
	Templates  contract.TemplateStore
	strictMode bool
}

// VerifyVP expects the given raw VerifiablePresentation to be of the correct type
// todo: type check?
func (v Verifier) VerifyVP(vp vc.VerifiablePresentation, checkTime *time.Time) (contract.VPVerificationResult, error) {
	// Extract the Irma message
	irmaProof := make([]VPProof, 0)
	if err := vp.UnmarshalProofValue(&irmaProof); err != nil {
		return nil, fmt.Errorf("could not verify VP: %w", err)
	}

	if len(irmaProof) != 1 {
		return nil, fmt.Errorf("could not verify VP: invalid number of proofs, got %d, want 1", len(irmaProof))
	}

	// Create the irma contract validator
	contractValidator := contractVerifier{irmaConfig: v.IrmaConfig, validContracts: v.Templates, strictMode: v.strictMode}
	signedContract, err := contractValidator.Parse(irmaProof[0].ProofValue)
	if err != nil {
		return nil, err
	}

	cvr, err := contractValidator.verifyAll(signedContract.(*signedIrmaContract), checkTime)
	if err != nil {
		return nil, err
	}

	signerAttributes, err := signedContract.SignerAttributes()
	if err != nil {
		return nil, fmt.Errorf("could not verify vp: could not get signer attributes: %w", err)
	}

	return irmaVPVerificationResult{
		validity:            contract.State(cvr.ValidationResult),
		reason:              cvr.FailureReason,
		vpType:              string(cvr.ContractFormat),
		disclosedAttributes: signerAttributes,
		contractAttributes:  signedContract.Contract().Params,
	}, nil
}

type irmaVPVerificationResult struct {
	validity            contract.State
	reason              string
	vpType              string
	disclosedAttributes map[string]string
	contractAttributes  map[string]string
}

func (I irmaVPVerificationResult) Validity() contract.State {
	return I.validity
}

func (I irmaVPVerificationResult) Reason() string {
	return I.reason
}

func (I irmaVPVerificationResult) VPType() string {
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
	case services.UsernameClaim:
		fallthrough
	case services.EmailTokenClaim:
		v = I.disclosedAttributes["sidn-pbdf.email.email"]
	case services.AssuranceLevelClaim:
		// Map DigiD levels to Nuts assurance levels.
		// Taken from https://www.logius.nl/domeinen/toegang/digid/documentatie/koppelvlakspecificatie-digid-saml-authenticatie
		switch strings.ToLower(I.disclosedAttributes["gemeente.personalData.digidlevel"]) {
		case "basis":
			fallthrough
		case "midden":
			v = "low"
		case "substantieel":
			v = "substantial"
		case "hoog":
			v = "high"
		default:
			log.Logger().Warnf("Unknown IRMA DigiD level: %s", I.disclosedAttributes["gemeente.personalData.digidlevel"])
		}
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
