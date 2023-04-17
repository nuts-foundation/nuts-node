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
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	issuer2 "github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

var employer = did.MustParseDID("did:nuts:8NYzfsndZJHh6GqzKiSBpyERrFxuX64z6tE5raa7nEjm")

const (
	testContract = "EN:PractitionerLogin:v3 I hereby declare to act on behalf of CareBears located in Caretown. This declaration is valid from Friday, 14 April 2023 13:40:00 to Saturday, 15 April 2023 13:40:00."
	familyName   = "Tester"
	initials     = "T"
	roleName     = "Verpleegkundige niveau 2"
	identifier   = "user@example.com"
)

func TestSessionStore_StartSigningSession(t *testing.T) {
	t.Run("add params to session", func(t *testing.T) {
		params := map[string]interface{}{
			"employer": employer.String(),
			"employee": struct {
				Identifier string `json:"identifier"`
				RoleName   string `json:"roleName"`
				Initials   string `json:"initials"`
				FamilyName string `json:"familyName"`
			}{
				identifier,
				roleName,
				initials,
				familyName,
			},
		}
		ss := NewSessionStore(nil).(sessionStore)

		sp, err := ss.StartSigningSession(testContract, params)
		require.NoError(t, err)
		session := ss.sessions[sp.SessionID()]
		require.NotNil(t, session)
		assert.Equal(t, testContract, session.contract)
		assert.Equal(t, SessionCreated, session.status)
		assert.Equal(t, employer.String(), session.Employer)
		assert.Equal(t, familyName, session.Employee.FamilyName)
		assert.Equal(t, initials, session.Employee.Initials)
		assert.Equal(t, identifier, session.Employee.Identifier)
		assert.Equal(t, roleName, session.Employee.RoleName)
	})
}

func TestSessionStore_SigningSessionStatus(t *testing.T) {
	params := map[string]interface{}{
		"employer": employer.String(),
		"employee": struct {
			Identifier string `json:"identifier"`
			RoleName   string `json:"roleName"`
			Initials   string `json:"initials"`
			FamilyName string `json:"familyName"`
		}{
			identifier,
			roleName,
			initials,
			familyName,
		},
	}
	testVC := vc.VerifiableCredential{}
	testVP := vc.VerifiablePresentation{}
	vcBytes, _ := os.ReadFile("./test/vc.json")
	vpBytes, _ := os.ReadFile("./test/vp.json")
	_ = json.Unmarshal(vcBytes, &testVC)
	_ = json.Unmarshal(vpBytes, &testVP)

	t.Run("status completed returns VP on SigningSessionResult", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewSessionStore(mockContext.vcr).(sessionStore)
		mockContext.issuer.EXPECT().Issue(context.TODO(), gomock.Any(), false, false).Return(&testVC, nil)
		mockContext.holder.EXPECT().BuildVP(context.TODO(), gomock.Len(1), gomock.Any(), &employer, true).Return(&testVP, nil)

		sp, err := ss.StartSigningSession(testContract, params)
		require.NoError(t, err)
		session := ss.sessions[sp.SessionID()]
		session.status = SessionCompleted
		ss.sessions[sp.SessionID()] = session
		result, err := ss.SigningSessionStatus(sp.SessionID())
		require.NoError(t, err)
		vp, err := result.VerifiablePresentation()
		require.NoError(t, err)
		assert.NotNil(t, vp)
	})

	t.Run("correct VC options are passed to issuer", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewSessionStore(mockContext.vcr).(sessionStore)
		mockContext.issuer.EXPECT().Issue(context.TODO(), gomock.Any(), false, false).DoAndReturn(
			func(arg0 interface{}, unsignedCredential interface{}, public interface{}, publish interface{}) (*vc.VerifiableCredential, error) {
				isPublic, ok := public.(bool)
				isPublished, ok2 := publish.(bool)
				credential, ok3 := unsignedCredential.(vc.VerifiableCredential)
				require.True(t, ok)
				require.True(t, ok2)
				require.True(t, ok3)
				assert.False(t, isPublic)
				assert.False(t, isPublished)
				assert.Equal(t, employer.URI(), credential.Issuer)
				assert.Equal(t, []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI("NutsEmployeeCredential")}, credential.Type)

				credentialSubject := credential.CredentialSubject[0].(map[string]interface{})
				assert.Equal(t, employer.String(), credentialSubject["id"])
				assert.Equal(t, "Organization", credentialSubject["@type"])
				member, ok := credentialSubject["member"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, identifier, member["identifier"])
				assert.Equal(t, roleName, member["roleName"])
				assert.Equal(t, "EmployeeRole", member["type"])
				member2, ok := member["member"].(map[string]string)
				require.True(t, ok)
				assert.Equal(t, initials, member2["initials"])
				assert.Equal(t, familyName, member2["familyName"])

				return &testVC, nil
			})
		mockContext.holder.EXPECT().BuildVP(context.TODO(), gomock.Len(1), gomock.Any(), &employer, true).Return(&testVP, nil)

		sp, err := ss.StartSigningSession(testContract, params)
		require.NoError(t, err)
		session := ss.sessions[sp.SessionID()]
		session.status = SessionCompleted
		ss.sessions[sp.SessionID()] = session
		_, err = ss.SigningSessionStatus(sp.SessionID())
		require.NoError(t, err)
	})
}

type mockContext struct {
	ctrl   *gomock.Controller
	vcr    *vcr.MockVCR
	holder *holder.MockHolder
	issuer *issuer2.MockIssuer
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)
	vcr := vcr.NewMockVCR(ctrl)
	holder := holder.NewMockHolder(ctrl)
	issuer := issuer2.NewMockIssuer(ctrl)
	vcr.EXPECT().Issuer().Return(issuer).AnyTimes()
	vcr.EXPECT().Holder().Return(holder).AnyTimes()

	return mockContext{
		ctrl:   ctrl,
		vcr:    vcr,
		issuer: issuer,
		holder: holder,
	}
}
