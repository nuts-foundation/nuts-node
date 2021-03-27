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
	"fmt"
	"os"
	"strings"

	"github.com/mdp/qrterminal/v3"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/logging"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/pkg/errors"
	irmago "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
)

// SessionPtr should be made private when v0 is removed
type SessionPtr struct {
	ID         string
	QrCodeInfo irmago.Qr `json:"sessionPtr"`
}

// SessionID returns the SessionID of the SessionPtr
func (s SessionPtr) SessionID() string {
	return s.ID
}

// Payload renders the IrmaQRCode as json according to irmago.Qr
func (s SessionPtr) Payload() []byte {
	jsonResult, _ := json.Marshal(s.QrCodeInfo)
	return jsonResult
}

// MarshalJSON marshals a custom session pointer json object for the IRMA means.
func (s SessionPtr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		QrCodeInfo irmago.Qr `json:"clientPtr"`
		ID         string    `json:"sessionID"`
	}{QrCodeInfo: s.QrCodeInfo, ID: s.ID})
}

// NutsIrmaSignedContract is the type of proof used in an Irma VP
const NutsIrmaSignedContract = "NutsIrmaSignedContract"

// StartSigningSession accepts a rawContractText and creates an IRMA signing session.
func (v Service) StartSigningSession(rawContractText string) (contract.SessionPointer, error) {
	// Put the template in an IRMA envelope
	signatureRequest := irmago.NewSignatureRequest(rawContractText)
	schemeManager := v.IrmaServiceConfig.IrmaSchemeManager

	c, err := contract.ParseContractString(rawContractText, v.ContractTemplates)
	if err != nil {
		return nil, err
	}

	var attributes irmago.AttributeCon
	for _, att := range c.Template.SignerAttributes {
		// Checks if attribute name start with a dot, if so, add the configured scheme manager.
		if strings.Index(att, ".") == 0 {
			att = fmt.Sprintf("%s%s", schemeManager, att)
		}
		attributes = append(attributes, irmago.NewAttributeRequest(att))
	}
	signatureRequest.Disclose = irmago.AttributeConDisCon{
		irmago.AttributeDisCon{
			attributes,
		},
	}

	// Start an IRMA session
	sessionPointer, token, err := v.IrmaSessionHandler.StartSession(signatureRequest, func(result *server.SessionResult) {
		logging.Log().Debugf("session done, result: %s", server.ToJson(result))
	})
	if err != nil {
		return nil, fmt.Errorf("error while creating session: %w", err)
	}
	logging.Log().Debugf("session created with token: %s", token)

	// Return the sessionPointer and sessionId
	challenge := SessionPtr{
		ID:         token,
		QrCodeInfo: *sessionPointer,
	}
	jsonResult := challenge.Payload()
	printQrCode(string(jsonResult))

	return challenge, nil
}

// SigningSessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
func (v Service) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	if result := v.IrmaSessionHandler.GetSessionResult(sessionID); result != nil {
		var (
			token string
		)
		if result.Signature != nil {
			c, err := contract.ParseContractString(result.Signature.Message, v.ContractTemplates)
			sic := &SignedIrmaContract{IrmaContract: *result.Signature, contract: c}
			if err != nil {
				return nil, err
			}

			le, err := v.legalEntityFromContract(sic)
			if err != nil {
				return nil, fmt.Errorf("could not create JWT for given session: %w", err)
			}

			token, err = v.CreateIdentityTokenFromIrmaContract(sic, *le)
			if err != nil {
				return nil, err
			}
		}
		result := SigningSessionResult{SessionResult: *result, NutsAuthToken: token}
		return result, nil
	}
	return nil, services.ErrSessionNotFound
}

// SigningSessionResult implements the SigningSessionResult interface and contains the
// SigningSessionResult from the IRMA means.
type SigningSessionResult struct {
	server.SessionResult
	// NutsAuthToken contains the JWT if the sessionStatus is DONE
	NutsAuthToken string `json:"nuts_auth_token"`
}

// Status returns the IRMA signing status
func (s SigningSessionResult) Status() string {
	return string(s.SessionResult.Status)
}

// VerifiablePresentation returns an IRMA implementation of the contract.VerifiablePresentation interface.
func (s SigningSessionResult) VerifiablePresentation() (contract.VerifiablePresentation, error) {

	irmaSig := s.Signature
	js, err := json.Marshal(irmaSig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create NutsIrmaPresentation")
	}
	b64 := base64.StdEncoding.EncodeToString(js)

	return VerifiablePresentation{
		VerifiablePresentationBase: contract.VerifiablePresentationBase{
			Context: []string{contract.VerifiableCredentialContext},
			Type:    []contract.VPType{contract.VerifiablePresentationType, VerifiablePresentationType},
		},
		Proof: VPProof{
			Proof: contract.Proof{
				Type: NutsIrmaSignedContract,
			},
			ProofValue: b64,
		},
	}, nil
}

func printQrCode(qrcode string) {
	config := qrterminal.Config{
		HalfBlocks: false,
		BlackChar:  qrterminal.WHITE,
		WhiteChar:  qrterminal.BLACK,
		Level:      qrterminal.M,
		Writer:     os.Stdout,
		QuietZone:  1,
	}
	qrterminal.GenerateWithConfig(qrcode, config)
}
