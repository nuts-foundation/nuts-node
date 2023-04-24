/*
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
 *
 */

package x509

import (
	"encoding/asn1"
	"fmt"
	"io/fs"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"

	"github.com/nuts-foundation/nuts-node/auth/assets"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/pki"
)

// UziSignedToken implements a SignedToken interface for contracts signed by the UZI means in the JwtX509Token form.
type UziSignedToken struct {
	jwtX509Token *JwtX509Token
	contract     *contract.Contract
}

// UziValidator can check Uzi signed JWTs.
// It can parse and validate a UziSignedToken which implements the SignedToken interface
type UziValidator struct {
	validator         *JwtX509Validator
	contractTemplates contract.TemplateStore
}

// UziEnv is used to indicate which Uzi environment (e.g. production, acceptation) should be used.
type UziEnv string

// UziProduction uses the production certificate tree:
// https://www.zorgcsp.nl/ca-certificaten
const UziProduction UziEnv = "production"

// UziAcceptation uses the acceptation certificate tree:
// https://acceptatie.zorgcsp.nl/ca-certificaten
const UziAcceptation UziEnv = "acceptation"

// A list of Uzi attribute names used to sign the message
// See table 12 on page 62 of the Certification Practice Statement (CPS) UZI-register v10.x
// https://zorgcsp.nl/Media/Default/documenten/2020-05-06_RK1%20CPS%20UZI-register%20V10.0.pdf
var uziAttributeNames = []string{
	"oidCa",
	"version",
	"uziNr",
	"cardType",
	"orgID",
	"roleCode",
	"agbCode",
}

// SignerAttributes returns the attributes from the Uzi card used in the signature.
// For more information on these attributes, see table 12 on page 62 of the Certification Practice Statement (CPS) UZI-register v10.x
// https://zorgcsp.nl/Media/Default/documenten/2020-05-06_RK1%20CPS%20UZI-register%20V10.0.pdf
func (t UziSignedToken) SignerAttributes() (map[string]string, error) {
	res := map[string]string{}
	otherNames, err := t.jwtX509Token.SubjectAltNameOtherNames()
	if err != nil {
		return nil, fmt.Errorf("could not extract SAN from certificate: %w", err)
	}

	for _, otherNameStr := range otherNames {
		parts := strings.Split(otherNameStr, "-")
		if len(parts) != len(uziAttributeNames) {
			continue
		}

		for idx, name := range uziAttributeNames {
			res[name] = parts[idx]
		}
	}

	return res, nil
}

// Contract returns the Contract signed by the Uzi means
func (t UziSignedToken) Contract() contract.Contract {
	return *t.contract
}

// LoadUziTruststore loads the embedded truststore for the corresponding UziEnv
func LoadUziTruststore(env UziEnv) (*core.TrustStore, error) {
	switch env {
	case UziProduction:
		return certsFromAssets([]string{
			"certs/uzi-prod/RootCA-G3.cer",
			"certs/uzi-prod/20190418_UZI-register_Medewerker_op_naam_CA_G3.cer",
			"certs/uzi-prod/20190418_UZI-register_Zorgverlener_CA_G3.cer",
			"certs/uzi-prod/DomOrganisatiePersoonCA-G3.cer",
			"certs/uzi-prod/UZI-register_Medewerker_op_naam_CA_G3.cer",
			"certs/uzi-prod/UZI-register_Zorgverlener_CA_G3.cer",
		})
	case UziAcceptation:
		return certsFromAssets([]string{
			"certs/uzi-acc/test_zorg_csp_root_ca_g3.cer",
			"certs/uzi-acc/test_uzi-register_medewerker_op_naam_ca_g3.cer",
			"certs/uzi-acc/test_zorg_csp_level_2_persoon_ca_g3.cer",
		})
	default:
		return nil, fmt.Errorf("unknown uzi environment: %s", env)
	}
}

// certsFromAssets allows for easy loading of the used UziCertificates.
// These certs are embedded into the binary for easy distribution.
func certsFromAssets(paths []string) (*core.TrustStore, error) {
	var rawCerts []byte
	for _, path := range paths {
		rawCert, err := fs.ReadFile(assets.FS, path)
		if err != nil {
			return nil, err
		}
		rawCert = append(rawCerts, rawCert...)
	}
	return core.ParseTrustStore(rawCerts)
}

func validUziSigningAlgs() []jwa.SignatureAlgorithm {
	return []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS512}
}

// NewUziValidator creates a new UziValidator.
// It accepts a *core.TrustStore containing the truststore for the correct UziEnv.
// The truststore must match that in the truststore in the provided pki.Validator.
// It accepts a contract template store which is used to check if the signed contract exists and is valid.
func NewUziValidator(truststore *core.TrustStore, contractTemplates contract.TemplateStore, pkiValidator pki.Validator) (validator *UziValidator, err error) {
	validator = &UziValidator{
		validator:         NewJwtX509Validator(truststore.RootCAs, truststore.IntermediateCAs, validUziSigningAlgs(), pkiValidator),
		contractTemplates: contractTemplates,
	}
	return
}

// Parse tries to parse a UZI ProofValue into a UziSignedToken
// A Uzi ProofValue is encoded as a JWT.
// The jwt should contain at least one certificate in the x509 header
// It tries to find the contract in the given contractStore.
// No other verifications are performed.
// Make sure to call Verify to perform the actual crypto verifications
func (u UziValidator) Parse(rawProofValue string) (services.SignedToken, error) {
	x509Token, err := u.validator.Parse(rawProofValue)
	if err != nil {
		return nil, err
	}
	tokenField, ok := x509Token.token.Get("message")
	if !ok {
		return nil, fmt.Errorf("jwt did not contain token field")
	}
	contractText, ok := tokenField.(string)
	if !ok {
		return nil, fmt.Errorf("token field should contain a string")
	}

	c, err := contract.ParseContractString(contractText, u.contractTemplates)
	if err != nil {
		return nil, err
	}

	return UziSignedToken{jwtX509Token: x509Token, contract: c}, nil
}

// extKeyUsageDocumentSigning is required for signing documents, according to the UZI spec.
var extKeyUsageDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}

// Verify performs all the crypto verifications like:
// Correct hashing algorithm
// Correct certificate tree
// Certificates are not revoked
// Verifies all the extra jwt fields like exp, iat and nbf.
// Verifies if the signer attributes are valid
func (u UziValidator) Verify(token services.SignedToken) error {
	x509SignedToken, ok := token.(UziSignedToken)
	if !ok {
		return fmt.Errorf("wrong token type")
	}
	_, err := token.SignerAttributes()
	if err != nil {
		return fmt.Errorf("invalid signer attributes in uzi certificate: %w", err)
	}
	err = u.validator.Verify(x509SignedToken.jwtX509Token)
	if err != nil {
		return err
	}

	// check if the certificate has the Extended Key usage for document signing
	keyUsageFound := false
	for _, keyUsage := range x509SignedToken.jwtX509Token.chain[0].UnknownExtKeyUsage {
		if keyUsage.Equal(extKeyUsageDocumentSigning) {
			keyUsageFound = true
			break
		}
	}
	if !keyUsageFound {
		return fmt.Errorf("certificate is missing the extended key usage for document signing (%s)", extKeyUsageDocumentSigning.String())
	}
	return nil
}
