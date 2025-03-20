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

package selfsigned

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"go.uber.org/mock/gomock"
	"os"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var vpValidTime, _ = time.Parse(time.RFC3339, "2023-04-20T13:00:00.000000+02:00")
var docTXTime, _ = time.Parse(time.RFC3339, "2023-04-14T12:00:00.000000+02:00")

func TestSigner_Validator_Roundtrip(t *testing.T) {
	// Setup VCR
	keyStore := crypto.NewMemoryStorage()
	cryptoInstance := crypto.NewTestCryptoInstance(orm.NewTestDatabase(t), keyStore)
	vcrContext := vcr.NewTestVCRContext(t, cryptoInstance)

	didDocument := did.Document{}
	didDocumentBytes, _ := os.ReadFile("./test/diddocument.json")
	_ = json.Unmarshal(didDocumentBytes, &didDocument)
	// Register DID document in VDR
	tx := didstore.TestTransaction(didDocument)
	tx.SigningTime = docTXTime
	err := vcrContext.DIDStore.Add(didDocument, tx)
	require.NoError(t, err)
	// Load private key so we can sign
	privateKeyData, _ := os.ReadFile("./test/private.pem")
	privateKey, err := util.PemToPrivateKey(privateKeyData)
	require.NoError(t, err)
	kid := didDocument.VerificationMethod[0].ID.String()
	err = keyStore.SavePrivateKey(context.Background(), kid, privateKey)
	require.NoError(t, err)
	err = cryptoInstance.Link(context.Background(), kid, kid, "1")
	require.NoError(t, err)

	// Sign VP
	issuanceDate := time.Date(2023, 4, 14, 13, 40, 0, 0, time.Local)
	issuer.TimeFunc = func() time.Time {
		return issuanceDate
	}
	signerService := NewSigner(vcrContext.VCR, "http://localhost").(*signer)
	roleName := "Administrator"
	issuerDID := "did:nuts:8NYzfsndZJHh6GqzKiSBpyERrFxuX64z6tE5raa7nEjm"
	createdVP, err := signerService.createVP(audit.TestContext(), types.Session{
		ExpiresAt: issuanceDate.Add(time.Hour * 24),
		Contract:  testContract,
		Employer:  issuerDID,
		Employee: types.Employee{
			Identifier: "user@examle.com",
			RoleName:   &roleName,
			Initials:   "Ad",
			FamilyName: "Min",
		}}, issuanceDate)
	require.NoError(t, err)

	// #2428: NutsEmployeeCredential does not need to be trusted, but the issuer needs to have a trusted NutsOrganizationCredential (chain of trust).
	//        Issue() automatically trusts the issuer, so untrust it for asserting trust chain behavior
	nutsOrgCred, err := vcrContext.VCR.Issuer().Issue(audit.TestContext(), createOrganizationCredential(issuerDID), issuer.CredentialOptions{
		Publish: false,
		Public:  false,
	})
	require.NoError(t, err)
	err = vcrContext.VCR.StoreCredential(*nutsOrgCred, nil) // Need to explicitly store, since we didn't publish it.
	require.NoError(t, err)
	err = vcrContext.VCR.Untrust(ssi.MustParseURI(credentialType), did.MustParseDID(issuerDID).URI())
	require.NoError(t, err)

	// Validate VP
	validatorService := NewValidator(vcrContext.VCR, contract.StandardContractTemplates)
	checkTime := issuanceDate.Add(time.Minute)
	result, err := validatorService.VerifyVP(*createdVP, &checkTime)

	require.NoError(t, err)
	assert.Empty(t, result.Reason())
	assert.Equal(t, contract.Valid, result.Validity())
}

func TestValidator_VerifyVP(t *testing.T) {
	vp := vc.VerifiablePresentation{}
	vpData, _ := os.ReadFile("./test/vp.json")
	_ = json.Unmarshal(vpData, &vp)
	testCredential := vc.VerifiableCredential{}
	vcData, _ := os.ReadFile("./test/vc.json")
	_ = json.Unmarshal(vcData, &testCredential)

	t.Run("ok using mocks", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, &vpValidTime).Return([]vc.VerifiableCredential{testCredential}, nil)
		mockContext.vcr.EXPECT().Search(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, &vpValidTime)

		require.NoError(t, err)
		assert.Empty(t, result.Reason())
		assert.Equal(t, contract.Valid, result.Validity())
		assert.Equal(t, "user@example.com", result.DisclosedAttribute(services.UsernameClaim))
		assert.Equal(t, "low", result.DisclosedAttribute(services.AssuranceLevelClaim))
		assert.Equal(t, "", result.DisclosedAttribute(services.PrefixTokenClaim))
		assert.Equal(t, "T", result.DisclosedAttribute(services.InitialsTokenClaim))
		assert.Equal(t, "Tester", result.DisclosedAttribute(services.FamilyNameTokenClaim))
		assert.Equal(t, "", result.DisclosedAttribute(services.EmailTokenClaim))
		assert.Equal(t, "Verpleegkundige niveau 2", result.DisclosedAttribute(services.UserRoleClaim))
	})
	t.Run("ok using mocks (without role)", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		credentialWithoutRole := vc.VerifiableCredential{}
		data, _ := os.ReadFile("./test/vc-without-role.json")
		_ = json.Unmarshal(data, &credentialWithoutRole)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, &vpValidTime).Return([]vc.VerifiableCredential{credentialWithoutRole}, nil)
		mockContext.vcr.EXPECT().Search(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, &vpValidTime)

		require.NoError(t, err)
		assert.Empty(t, result.DisclosedAttribute(services.UserRoleClaim))
	})

	t.Run("technical error on verify", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, nil).Return(nil, errors.New("error"))

		_, err := ss.VerifyVP(vp, nil)

		assert.Error(t, err)
	})

	t.Run("verification error on verify", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, nil).Return(nil, verifier.VerificationError{})

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "verification error: ", result.Reason())
	})

	t.Run("ok using in-memory DBs", func(t *testing.T) {
		keyStore := crypto.NewMemoryStorage()
		cryptoInstance := crypto.NewTestCryptoInstance(orm.NewTestDatabase(t), keyStore)
		vcrContext := vcr.NewTestVCRContext(t, cryptoInstance)
		var didDocument did.Document
		ddBytes, _ := os.ReadFile("./test/diddocument.json")
		err := json.Unmarshal(ddBytes, &didDocument)
		require.NoError(t, err)

		// Load private key so we can sign
		privateKeyData, _ := os.ReadFile("./test/private.pem")
		privateKey, err := util.PemToPrivateKey(privateKeyData)
		require.NoError(t, err)
		kid := didDocument.VerificationMethod[0].ID.String()
		err = keyStore.SavePrivateKey(context.Background(), kid, privateKey)
		require.NoError(t, err)
		err = cryptoInstance.Link(context.Background(), kid, kid, "1")
		require.NoError(t, err)

		ss := NewValidator(vcrContext.VCR, contract.StandardContractTemplates)
		// test transaction for DIDStore ordering
		tx := didstore.TestTransaction(didDocument)
		tx.SigningTime = docTXTime
		err = vcrContext.DIDStore.Add(didDocument, tx)
		require.NoError(t, err)
		// #2428: NutsEmployeeCredential issuer needs a trusted NutsOrganizationCredential
		issuer.TimeFunc = func() time.Time {
			// Issued credentials get the current date/time as issuance date,
			// need to set it to a fixed value that corresponds with vpValidTime for testing.
			// Otherwise, the NutsOrganizationCredential is not yet valid or might be expired.
			return vpValidTime.Add(-1 * time.Hour)
		}
		nutsOrgCred, err := vcrContext.VCR.Issuer().Issue(audit.TestContext(), createOrganizationCredential(didDocument.ID.String()), issuer.CredentialOptions{
			Publish: false,
			Public:  false,
		})
		require.NoError(t, err)
		err = vcrContext.VCR.StoreCredential(*nutsOrgCred, &vpValidTime) // Need to explicitly store, since we didn't publish it.
		require.NoError(t, err)

		result, err := ss.VerifyVP(vp, &vpValidTime)

		require.NoError(t, err)
		assert.Empty(t, result.Reason())
		assert.Equal(t, contract.Valid, result.Validity())
	})

	t.Run("error - broken contract", func(t *testing.T) {
		mockContext := newMockContext(t)
		vp := vc.VerifiablePresentation{}
		vpData, _ := os.ReadFile("./test/vp_invalid_contract.json")
		_ = json.Unmarshal(vpData, &vp)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)
		mockContext.vcr.EXPECT().Search(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "invalid contract text: could not extract contract version, language and type", result.Reason())
	})

	t.Run("error - contract not valid for given time", func(t *testing.T) {
		mockContext := newMockContext(t)
		now := time.Now()
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, &now).Return([]vc.VerifiableCredential{testCredential}, nil)
		mockContext.vcr.EXPECT().Search(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, &now)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "invalid contract text: invalid period: contract is expired", result.Reason())
	})

	t.Run("error - missing credential", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, nil).Return([]vc.VerifiableCredential{}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "exactly 1 EmployeeIdentityCredential is required", result.Reason())
	})

	t.Run("error - missing proof", func(t *testing.T) {
		mockContext := newMockContext(t)
		vp := vc.VerifiablePresentation{}
		vpData, _ := os.ReadFile("./test/vp_missing_proof.json")
		_ = json.Unmarshal(vpData, &vp)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "exactly 1 Proof is required", result.Reason())
	})

	t.Run("error - incorrect proof type", func(t *testing.T) {
		mockContext := newMockContext(t)
		vp := vc.VerifiablePresentation{}
		vpData, _ := os.ReadFile("./test/vp_incorrect_proof_type.json")
		_ = json.Unmarshal(vpData, &vp)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "proof must be of type JsonWebSignature2020", result.Reason())
	})

	t.Run("error - incorrect signer", func(t *testing.T) {
		mockContext := newMockContext(t)
		vp := vc.VerifiablePresentation{}
		vpData, _ := os.ReadFile("./test/vp_incorrect_signer.json")
		_ = json.Unmarshal(vpData, &vp)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "signer must be credential issuer", result.Reason())
	})

	t.Run("error - incorrect signer", func(t *testing.T) {
		mockContext := newMockContext(t)
		credential := testCredential
		vp := vc.VerifiablePresentation{}
		vpData, _ := os.ReadFile("./test/vp_incorrect_subject.json")
		_ = json.Unmarshal(vpData, &vp)
		credential.Issuer = did.MustParseDID("did:nuts:a").URI()
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, nil).Return([]vc.VerifiableCredential{credential}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "signer must be credentialSubject", result.Reason())
	})

	t.Run("error - issuer does not have trusted NutsOrganizationCredential", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewValidator(mockContext.vcr, contract.StandardContractTemplates)
		credentialWithoutRole := vc.VerifiableCredential{}
		data, _ := os.ReadFile("./test/vc-without-role.json")
		_ = json.Unmarshal(data, &credentialWithoutRole)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, true, &vpValidTime).Return([]vc.VerifiableCredential{credentialWithoutRole}, nil)
		mockContext.vcr.EXPECT().Search(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{}, nil)

		result, err := ss.VerifyVP(vp, &vpValidTime)

		require.NoError(t, err)
		assert.Empty(t, result.DisclosedAttribute(services.UserRoleClaim))
	})
}

func Test_validateRequiredAttributes(t *testing.T) {
	valid := types.EmployeeIdentityCredentialSubject{
		Type: "Organization",
		Member: types.EmployeeIdentityCredentialMember{
			Identifier: "test@example.com",
			Member: types.EmployeeIdentityCredentialMemberMember{
				FamilyName: "Tester",
				Initials:   "T",
				Type:       "Person",
			},
			Type: "EmployeeRole",
		},
	}

	t.Run("ok", func(t *testing.T) {
		cs := valid

		err := validateRequiredAttributes(cs)

		assert.NoError(t, err)
	})

	tests := []struct {
		expected  string
		parameter func(*types.EmployeeIdentityCredentialSubject)
	}{
		{
			"credentialSubject.type must be \"Organization\"",
			func(subject *types.EmployeeIdentityCredentialSubject) {
				subject.Type = "Not Organization"
			},
		},
		{
			"credentialSubject.member.identifier is required",
			func(subject *types.EmployeeIdentityCredentialSubject) {
				subject.Member.Identifier = ""
			},
		},
		{
			"credentialSubject.member.member.initials is required",
			func(subject *types.EmployeeIdentityCredentialSubject) {
				subject.Member.Member.Initials = ""
			},
		},
		{
			"credentialSubject.member.member.familyName is required",
			func(subject *types.EmployeeIdentityCredentialSubject) {
				subject.Member.Member.FamilyName = ""
			},
		},
		{
			"credentialSubject.member.type must be \"EmployeeRole\"",
			func(subject *types.EmployeeIdentityCredentialSubject) {
				subject.Member.Type = "Not EmployeeRole"
			},
		},
		{
			"credentialSubject.member.member.type must be \"Person\"",
			func(subject *types.EmployeeIdentityCredentialSubject) {
				subject.Member.Member.Type = "Not Person"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			cs := valid
			test.parameter(&cs)
			err := validateRequiredAttributes(cs)

			assert.EqualError(t, err, test.expected)
		})
	}
}

// tests for selfsignedVerificationResult
func Test_selfsignedVerificationResult(t *testing.T) {
	t.Run("ok - getters return expected values", func(t *testing.T) {
		ssvr := selfsignedVerificationResult{
			Status:              "success",
			InvalidReason:       "timeout",
			contractAttributes:  map[string]string{"cAttr1": "test1"},
			disclosedAttributes: map[string]string{"dAttr1": "test2"},
		}

		vr := contract.VPVerificationResult(ssvr)

		assert.Equal(t, contract.State("success"), vr.Validity())
		assert.Equal(t, "timeout", vr.Reason())
		assert.Equal(t, map[string]string{"cAttr1": "test1"}, vr.ContractAttributes())
		assert.Equal(t, map[string]string{"dAttr1": "test2"}, vr.DisclosedAttributes())
		assert.Equal(t, "NutsSelfSignedPresentation", vr.VPType())
		assert.Equal(t, "test1", vr.ContractAttribute("cAttr1"))
		assert.Equal(t, "test2", vr.DisclosedAttribute("dAttr1"))
	})
}

func createOrganizationCredential(issuerDID string) vc.VerifiableCredential {
	orgCred := vc.VerifiableCredential{
		Context: []ssi.URI{credential.NutsV1ContextURI},
		Type:    []ssi.URI{ssi.MustParseURI("NutsOrganizationCredential")},
		Issuer:  did.MustParseDID(issuerDID).URI(),
		CredentialSubject: []map[string]any{
			{
				"id": issuerDID,
				"organization": map[string]string{
					"name": "CareBears",
					"city": "CareTown",
				},
			},
		},
	}
	return orgCred
}
