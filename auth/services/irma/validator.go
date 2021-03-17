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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nuts-foundation/go-did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	irmaserver2 "github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/nuts-foundation/nuts-node/auth/services"

	"github.com/nuts-foundation/nuts-node/auth/contract"

	irma "github.com/privacybydesign/irmago"
	irmaserver "github.com/privacybydesign/irmago/server"
)

// todo rename to verifier

// VerifiablePresentationType is the irma verifiable presentation type
const VerifiablePresentationType = contract.VPType("NutsIrmaPresentation")

// ContractFormat holds the readable identifier of this signing means.
const ContractFormat = contract.SigningMeans("irma")

func init() {
	jwt.RegisterCustomField("sig", "")
}

// Service validates contracts using the IRMA logic.
type Service struct {
	IrmaSessionHandler SessionHandler
	IrmaConfig         *irma.Configuration
	IrmaServiceConfig  ValidatorConfig
	DIDResolver       types.Resolver
	Signer            nutsCrypto.JWTSigner
	ContractTemplates contract.TemplateStore
	StrictMode        bool
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

// VerifyVP expects the given raw VerifiablePresentation to be of the correct type
// todo: type check?
func (v Service) VerifyVP(rawVerifiablePresentation []byte, checkTime *time.Time) (*contract.VPVerificationResult, error) {
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

	return &contract.VPVerificationResult{
		Validity:            contract.State(cvr.ValidationResult),
		VPType:              contract.VPType(cvr.ContractFormat),
		DisclosedAttributes: signerAttributes,
		ContractAttributes:  signedContract.Contract().Params,
	}, nil
}

func (v Service) legalEntityFromContract(_ *SignedIrmaContract) (*did.DID, error) {
	// TODO: Implement this (https://github.com/nuts-foundation/nuts-node/issues/84)
	return vdr.TestDIDA, nil
}

// CreateIdentityTokenFromIrmaContract from a signed irma contract. Returns a JWT signed with the provided legalEntity.
func (v Service) CreateIdentityTokenFromIrmaContract(contract *SignedIrmaContract, legalEntity did.DID) (string, error) {
	signature, err := json.Marshal(contract.IrmaContract)
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	if err != nil {
		return "", err
	}
	signingKey, err := v.DIDResolver.ResolveSigningKeyID(legalEntity, nil)
	if err != nil {
		return "", err
	}
	payload := services.NutsIdentityToken{
		Signature: encodedSignature,
		Type:      services.IrmaFormat,
		KeyID:     signingKey,
	}
	claims, err := convertPayloadToClaims(payload)
	if err != nil {
		return "", fmt.Errorf("could not construct claims: %w", err)
	}
	claims[jwt.IssuerKey] = legalEntity.String()
	return v.Signer.SignJWT(claims, signingKey)
}

// convertPayloadToClaims converts a nutsJwt struct to a map of strings so it can be signed with the crypto module
func convertPayloadToClaims(payload services.NutsIdentityToken) (map[string]interface{}, error) {

	var (
		jsonString []byte
		err        error
		claims     map[string]interface{}
	)

	if jsonString, err = json.Marshal(payload); err != nil {
		return nil, fmt.Errorf("could not marshall payload: %w", err)
	}

	if err := json.Unmarshal(jsonString, &claims); err != nil {
		return nil, fmt.Errorf("could not unmarshal string: %w", err)
	}

	return claims, nil
}

// SessionHandler is an abstraction for the Irma Server, mainly for enabling better testing
type SessionHandler interface {
	GetSessionResult(token string) *irmaserver.SessionResult
	StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error)
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
	return d.I.GetSessionResult(token)
}

// StartSession forwards to Irma Server instance
func (d *DefaultIrmaSessionHandler) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return d.I.StartSession(request, handler)
}

// ErrLegalEntityNotProvided indicates that the legalEntity is missing
var ErrLegalEntityNotProvided = errors.New("legalEntity not provided")
