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
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/nuts-foundation/nuts-node/auth/services"
	irma "github.com/privacybydesign/irmago"
)

// signedIrmaContract holds the contract and additional methods to parse and validate.
type signedIrmaContract struct {
	irmaContract irma.SignedMessage
	contract     *contract.Contract
	attributes   map[string]string
	// Cached proofStatus because attribute extraction and signature validation is performed during parsing
	proofStatus irma.ProofStatus
}

// SignerAttributes returns a map of irma attributes minus the root:
//
//	{
//	  "gemeente.personalData.fullname": "Henk de Vries",
//	  "sidn-pbdf.email.email": "henk.devries@example.com",
//	},
func (s signedIrmaContract) SignerAttributes() (map[string]string, error) {
	return s.attributes, nil
}

// Contract returns the signed contract.Contract by the irma contract
func (s signedIrmaContract) Contract() contract.Contract {
	return *s.contract
}

// A IrmaContract is valid when:
//
//	it has a valid signature
//	it contains a message that is a known Contract
//	its signature is signed with all attributes required by the Contract
//	it has a valid time period
//	the acting party named in the contract is the same as the one making the request
type contractVerifier struct {
	irmaConfig     *irma.Configuration
	validContracts contract.TemplateStore
	strictMode     bool
}

// Parse an IRMA Authentication Token. A token is a base64 encoded IRMA contract.
func (cv *contractVerifier) Parse(rawAuthToken string) (services.SignedToken, error) {
	decodedAuthToken, err := base64.StdEncoding.DecodeString(rawAuthToken)
	if err != nil {
		return nil, fmt.Errorf("unable to Parse VP: %w", err)
	}
	return cv.ParseIrmaContract(decodedAuthToken)
}

// ParseIrmaContract accepts a json encoded irma contract and performs the following operations/validations:
// * Checks the irma signature
// * Parses the signed attributes
// * Checks if the contract message is set
// * Parses the contract from the message
// Returns a signedIrmaContract
// Note that the irma contract validation is performed during the parsing phase.
// This is because parsing and attribute extraction is done in one step.
func (cv *contractVerifier) ParseIrmaContract(jsonIrmaContract []byte) (services.SignedToken, error) {
	signedIrmaContract := &signedIrmaContract{}

	if err := json.Unmarshal(jsonIrmaContract, &signedIrmaContract.irmaContract); err != nil {
		return nil, fmt.Errorf("could not parse IRMA contract: %w", err)
	}

	if signedIrmaContract.irmaContract.Message == "" {
		return nil, fmt.Errorf("could not parse contract: empty message")
	}

	attributes, status, err := signedIrmaContract.irmaContract.Verify(cv.irmaConfig, nil)
	if err != nil {
		return nil, err
	}
	signerAttributes := parseSignerAttributes(cv.strictMode, attributes)

	contractMessage := signedIrmaContract.irmaContract.Message
	c, err := contract.ParseContractString(contractMessage, cv.validContracts)
	if err != nil {
		return nil, err
	}

	signedIrmaContract.contract = c
	signedIrmaContract.proofStatus = status
	signedIrmaContract.attributes = signerAttributes

	return signedIrmaContract, nil
}

// Verify checks if the signedIrmaContract:
// * Has a valid irma signature (stored in proofStatus during parsing)
// * Has a valid contract
// Returns an error if one of the checks fails
func (cv *contractVerifier) Verify(token services.SignedToken) error {
	irmaToken, ok := token.(signedIrmaContract)
	if !ok {
		return errors.New("could not verify token: could not cast token to SignedIrmaToken")
	}
	if irmaToken.proofStatus != irma.ProofStatusValid {
		return fmt.Errorf("irma proof invalid: %s", irmaToken.proofStatus)
	}
	return token.Contract().Verify()
}

func parseSignerAttributes(strictMode bool, attributes [][]*irma.DisclosedAttribute) map[string]string {
	if len(attributes) == 0 {
		return map[string]string{}
	}
	// take the attributes rawvalue and add them to a list.
	disclosedAttributes := make(map[string]string, len(attributes[0]))
	for _, att := range attributes[0] {
		// Check schemeManager. Only the pdbf root is accepted in strictMode.
		schemeManager := att.Identifier.Root()
		if strictMode && schemeManager != "pbdf" {
			log.Logger().Infof("IRMA schemeManager %s is not valid in strictMode", schemeManager)
			continue
		}
		identifier := att.Identifier.String()
		// strip of the schemeManager
		if i := strings.Index(identifier, "."); i != -1 {
			identifier = identifier[i+1:]
		}
		disclosedAttributes[identifier] = *att.RawValue
	}
	return disclosedAttributes
}

// verifyAll verifies the contract contents, the signer attributes and the proof status and returns a ContractValidationResult
// It can be used by both the old JWT verifier and the new VPVerifier
func (cv *contractVerifier) verifyAll(signedContract *signedIrmaContract, checkTime *time.Time) (*services.ContractValidationResult, error) {
	res := &services.ContractValidationResult{
		ContractFormat: services.IrmaFormat,
	}

	if signedContract.proofStatus == irma.ProofStatusValid {
		res.ValidationResult = services.Valid
		res.DisclosedAttributes = signedContract.attributes
	} else {
		res.ValidationResult = services.Invalid
		res.FailureReason = fmt.Sprintf("IRMA proof invalid: %s", signedContract.proofStatus)
	}

	var err error
	res, err = cv.validateContractContents(signedContract, res, checkTime)
	if err != nil {
		return nil, err
	}
	return cv.verifyRequiredAttributes(signedContract, res)
}

// validateContractContents validates at the actual contract contents.
// Is the timeframe valid and does the common name corresponds with the contract message.
func (cv *contractVerifier) validateContractContents(signedContract *signedIrmaContract, validationResult *services.ContractValidationResult, checkTimeP *time.Time) (*services.ContractValidationResult, error) {
	if validationResult.ValidationResult == services.Invalid {
		return validationResult, nil
	}

	checkTime := time.Now()
	if checkTimeP != nil {
		checkTime = *checkTimeP
	}
	// Validate time frame
	if err := signedContract.contract.VerifyForGivenTime(checkTime); err != nil {
		validationResult.ValidationResult = services.Invalid
		validationResult.FailureReason = err.Error()
		return validationResult, nil
	}

	// all valid fill contractAttributes
	validationResult.ContractAttributes = signedContract.contract.Params

	return validationResult, nil
}

// verifyRequiredAttributes checks if all attributes required by a contract template are actually present in the signature
func (cv *contractVerifier) verifyRequiredAttributes(signedIrmaContract *signedIrmaContract, validationResult *services.ContractValidationResult) (*services.ContractValidationResult, error) {
	if validationResult.ValidationResult == services.Invalid {
		return validationResult, nil
	}

	contractTemplate := signedIrmaContract.contract.Template

	// use a map to ignore duplicates. Allows us to compare lengths
	validationRes := make(map[string]bool)

	requiredAttributes := contractTemplate.SignerAttributes

	for disclosedAtt := range validationResult.DisclosedAttributes {
		// e.g. gemeente.personalData.firstnames
		for _, requiredAttribute := range requiredAttributes {
			// e.g. .gemeente.personalData.firstnames
			if strings.HasSuffix(requiredAttribute, disclosedAtt) {
				validationRes[requiredAttribute] = true
			}
		}
	}

	if len(validationRes) != len(requiredAttributes) {
		foundAttributes := make([]string, len(validationRes))
		for k := range validationRes {
			foundAttributes = append(foundAttributes, k)
		}

		disclosedAttributes := make([]string, len(validationResult.DisclosedAttributes))
		for k := range validationResult.DisclosedAttributes {
			disclosedAttributes = append(disclosedAttributes, k)
		}
		validationResult.ValidationResult = services.Invalid
		msg := fmt.Sprintf("missing required attributes in signature. found: %v, needed: %v, disclosed: %v", foundAttributes, requiredAttributes, disclosedAttributes)
		validationResult.FailureReason = msg
		log.Logger().Warn(msg)
	}

	return validationResult, nil
}
