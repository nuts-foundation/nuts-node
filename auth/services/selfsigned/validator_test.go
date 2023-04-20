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
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"os"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	vcr2 "github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var vpValidTime, _ = time.Parse(time.RFC3339, "2023-04-20T13:00:00.000000+02:00")
var docTXTime, _ = time.Parse(time.RFC3339, "2023-04-14T12:00:00.000000+02:00")

func TestSessionStore_VerifyVP(t *testing.T) {

	vp := vc.VerifiablePresentation{}
	vpData, _ := os.ReadFile("./test/vp.json")
	_ = json.Unmarshal(vpData, &vp)
	testCredential := vc.VerifiableCredential{}
	vcData, _ := os.ReadFile("./test/vc.json")
	_ = json.Unmarshal(vcData, &testCredential)

	t.Run("ok using mocks", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, &vpValidTime).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, &vpValidTime)

		require.NoError(t, err)
		assert.Empty(t, result.Reason())
		assert.Equal(t, contract.Valid, result.Validity())
	})

	t.Run("technical error on verify", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return(nil, errors.New("error"))

		_, err := ss.VerifyVP(vp, nil)

		assert.Error(t, err)
	})

	t.Run("verification error on verify", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return(nil, verifier.VerificationError{})

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "verification error: ", result.Reason())
	})

	t.Run("ok using in-memory DBs", func(t *testing.T) {
		vcrContext := vcr2.NewTestVCRContext(t)
		ss := NewService(vcrContext.VCR, contract.StandardContractTemplates).(*service)
		didDocument := did.Document{}
		ddBytes, _ := os.ReadFile("./test/diddocument.json")
		_ = json.Unmarshal(ddBytes, &didDocument)
		// test transaction for DIDStore ordering
		tx := didstore.TestTransaction(didDocument)
		tx.SigningTime = docTXTime
		err := vcrContext.DIDStore.Add(didDocument, tx)
		require.NoError(t, err)
		// Trust issuer, only needed for test
		vcrContext.VCR.Trust(ssi.MustParseURI(credentialType), didDocument.ID.URI())

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
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "invalid contract text: could not extract contract version, language and type", result.Reason())
	})

	t.Run("error - contract not valid for given time", func(t *testing.T) {
		mockContext := newMockContext(t)
		now := time.Now()
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, &now).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, &now)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "invalid contract text: invalid period: contract is expired", result.Reason())
	})

	t.Run("error - missing credential", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return([]vc.VerifiableCredential{}, nil)

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
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

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
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

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
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

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
		ss := NewService(mockContext.vcr, contract.StandardContractTemplates).(*service)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return([]vc.VerifiableCredential{credential}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
		assert.Equal(t, "signer must be credentialSubject", result.Reason())
	})
}

func Test_validateRequiredAttributes(t *testing.T) {
	valid := employeeIdentityCredentialSubject{
		Type: "Organization",
		Member: employeeIdentityCredentialMember{
			Identifier: "test@example.com",
			Member: employeeIdentityCredentialMemberMember{
				FamilyName: "Tester",
				Initials:   "T",
				Type:       "Person",
			},
			RoleName: "VP",
			Type:     "EmployeeRole",
		},
	}

	t.Run("ok", func(t *testing.T) {
		cs := valid

		err := validateRequiredAttributes(cs)

		assert.NoError(t, err)
	})

	tests := []struct {
		expected  string
		parameter func(*employeeIdentityCredentialSubject)
	}{
		{
			"credentialSubject.type must be \"Organization\"",
			func(subject *employeeIdentityCredentialSubject) {
				subject.Type = "Not Organization"
			},
		},
		{
			"credentialSubject.member.identifier is required",
			func(subject *employeeIdentityCredentialSubject) {
				subject.Member.Identifier = ""
			},
		},
		{
			"credentialSubject.member.member.initials is required",
			func(subject *employeeIdentityCredentialSubject) {
				subject.Member.Member.Initials = ""
			},
		},
		{
			"credentialSubject.member.member.familyName is required",
			func(subject *employeeIdentityCredentialSubject) {
				subject.Member.Member.FamilyName = ""
			},
		},
		{
			"credentialSubject.member.type must be \"EmployeeRole\"",
			func(subject *employeeIdentityCredentialSubject) {
				subject.Member.Type = "Not EmployeeRole"
			},
		},
		{
			"credentialSubject.member.member.type must be \"Person\"",
			func(subject *employeeIdentityCredentialSubject) {
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
