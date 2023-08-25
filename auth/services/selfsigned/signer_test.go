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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"os"
	"testing"
)

var employer = did.MustParseDID("did:nuts:8NYzfsndZJHh6GqzKiSBpyERrFxuX64z6tE5raa7nEjm")

const (
	testContract = "EN:PractitionerLogin:v3 I hereby declare to act on behalf of CareBears located in Caretown. This declaration is valid from Friday, 14 April 2023 13:40:00 until Saturday, 15 April 2023 13:40:00."
	familyName   = "Tester"
	initials     = "T"
	roleName     = "Verpleegkundige niveau 2"
	identifier   = "user@example.com"
)

func TestSessionStore_StartSigningSession(t *testing.T) {
	params := map[string]interface{}{
		"employer": employer.String(),
		"employee": map[string]interface{}{
			"identifier": identifier,
			"roleName":   roleName,
			"initials":   initials,
			"familyName": familyName,
		},
	}

	t.Run("add params to session", func(t *testing.T) {
		ss := NewSigner(nil, "").(*signer)
		sp, err := ss.StartSigningSession(contract.Contract{RawContractText: testContract}, params)
		require.NoError(t, err)
		session, _ := ss.store.Load(sp.SessionID())
		require.NotNil(t, session)
		assert.Equal(t, testContract, session.Contract)
		assert.Equal(t, types.SessionCreated, session.Status)
		assert.Equal(t, employer.String(), session.Employer)
		assert.Equal(t, familyName, session.Employee.FamilyName)
		assert.Equal(t, initials, session.Employee.Initials)
		assert.Equal(t, identifier, session.Employee.Identifier)
		assert.Equal(t, roleName, *session.Employee.RoleName)
	})

	t.Run("secret and session ID are different for each session", func(t *testing.T) {
		const iterations = 100
		service := NewSigner(nil, "").(*signer)
		store := service.store.(*memorySessionStore)

		for i := 0; i < iterations; i++ {
			_, err := service.StartSigningSession(contract.Contract{RawContractText: testContract}, params)
			require.NoError(t, err)
			require.Len(t, store.sessions, i+1)
		}

		// Check every session has a unique secret
		for id, session := range store.sessions {
			require.Len(t, id, 32)
			require.Len(t, session.Secret, 32)
			for _, otherSession := range store.sessions {
				if session == otherSession {
					continue
				}
				require.NotEqual(t, session.Secret, otherSession.Secret)
			}
		}
	})

	t.Run("error on invalid JSON", func(t *testing.T) {
		params := map[string]interface{}{
			"broken": func() {},
		}

		ss := NewSigner(nil, "").(*signer)
		_, err := ss.StartSigningSession(contract.Contract{RawContractText: testContract}, params)

		require.Error(t, err)
	})
}

func TestSessionStore_SigningSessionStatus(t *testing.T) {
	ctx := context.TODO()
	params := map[string]interface{}{
		"employer": employer.String(),
		"employee": map[string]interface{}{
			"identifier": identifier,
			"roleName":   roleName,
			"initials":   initials,
			"familyName": familyName,
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
		ss := NewSigner(mockContext.vcr, "").(*signer)
		mockContext.issuer.EXPECT().Issue(context.TODO(), gomock.Any(), false, false).Return(&testVC, nil)
		mockContext.wallet.EXPECT().Present(context.TODO(), gomock.Len(1), gomock.Any(), &employer, true).Return(&testVP, nil)

		sp, err := ss.StartSigningSession(contract.Contract{RawContractText: testContract}, params)
		require.NoError(t, err)
		s, _ := ss.store.Load(sp.SessionID())
		s.Status = types.SessionCompleted
		ss.store.Store(sp.SessionID(), s)
		result, err := ss.SigningSessionStatus(ctx, sp.SessionID())
		require.NoError(t, err)
		vp, err := result.VerifiablePresentation()
		require.NoError(t, err)
		assert.NotNil(t, vp)
	})

	t.Run("err - status changed during request", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStore := types.NewMockSessionStore(ctrl)
		mockStore.EXPECT().Load("123").Return(
			types.Session{
				Status: types.SessionCompleted,
			}, true)
		mockStore.EXPECT().CheckAndSetStatus("123", types.SessionCompleted, types.SessionVPRequested).Return(false)
		mockStore.EXPECT().Delete("123")
		ss := signer{store: mockStore}
		res, err := ss.SigningSessionStatus(ctx, "123")
		assert.ErrorIs(t, err, services.ErrSessionNotFound)
		assert.Nil(t, res)
	})

	t.Run("ok - all terminal statuses get deleted", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockStore := types.NewMockSessionStore(ctrl)
		terminalStates := []string{
			types.SessionErrored,
			types.SessionCancelled,
			types.SessionExpired,
			types.SessionVPRequested,
		}
		for _, state := range terminalStates {
			mockStore.EXPECT().Load("123").Return(
				types.Session{
					Status: state,
				}, true)
		}

		mockStore.EXPECT().Delete("123").Times(len(terminalStates))

		ss := signer{store: mockStore}
		for _, state := range terminalStates {
			res, err := ss.SigningSessionStatus(ctx, "123")
			assert.NoError(t, err)
			assert.Equal(t, state, res.Status())
		}
	})

	t.Run("correct VC options are passed to issuer", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewSigner(mockContext.vcr, "").(*signer)
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
				assert.Equal(t, []ssi.URI{ssi.MustParseURI("NutsEmployeeCredential")}, credential.Type)

				credentialSubject := credential.CredentialSubject[0].(map[string]interface{})
				assert.Equal(t, employer.String(), credentialSubject["id"])
				assert.Equal(t, "Organization", credentialSubject["type"])
				require.IsType(t, map[string]interface{}{}, credentialSubject["member"])
				member := credentialSubject["member"].(map[string]interface{})
				assert.Equal(t, identifier, member["identifier"])
				assert.Equal(t, roleName, member["roleName"])
				assert.Equal(t, "EmployeeRole", member["type"])
				require.IsType(t, map[string]interface{}{}, member["member"])
				member2 := member["member"].(map[string]interface{})
				assert.Equal(t, initials, member2["initials"])
				assert.Equal(t, familyName, member2["familyName"])

				return &testVC, nil
			})
		mockContext.wallet.EXPECT().Present(context.TODO(), gomock.Len(1), gomock.Any(), &employer, true).Return(&testVP, nil)

		sp, err := ss.StartSigningSession(contract.Contract{RawContractText: testContract}, params)
		require.NoError(t, err)
		s, _ := ss.store.Load(sp.SessionID())
		s.Status = types.SessionCompleted
		ss.store.Store(sp.SessionID(), s)
		_, err = ss.SigningSessionStatus(ctx, sp.SessionID())
		require.NoError(t, err)
	})

	t.Run("error for unknown session", func(t *testing.T) {
		ss := NewSigner(nil, "")

		_, err := ss.SigningSessionStatus(ctx, "unknown")

		assert.Equal(t, services.ErrSessionNotFound, err)
	})

	t.Run("error on VC issuance", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewSigner(mockContext.vcr, "").(*signer)
		mockContext.issuer.EXPECT().Issue(context.TODO(), gomock.Any(), false, false).Return(nil, errors.New("error"))

		sp, err := ss.StartSigningSession(contract.Contract{RawContractText: testContract}, params)
		require.NoError(t, err)
		s, _ := ss.store.Load(sp.SessionID())
		s.Status = types.SessionCompleted
		ss.store.Store(sp.SessionID(), s)
		_, err = ss.SigningSessionStatus(ctx, sp.SessionID())

		assert.EqualError(t, err, "failed to create VerifiablePresentation: issue VC failed: error")
	})

	t.Run("error on building VP", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewSigner(mockContext.vcr, "").(*signer)
		mockContext.issuer.EXPECT().Issue(context.TODO(), gomock.Any(), false, false).Return(&testVC, nil)
		mockContext.wallet.EXPECT().Present(context.TODO(), gomock.Len(1), gomock.Any(), &employer, true).Return(nil, errors.New("error"))

		sp, err := ss.StartSigningSession(contract.Contract{RawContractText: testContract}, params)
		require.NoError(t, err)
		s, _ := ss.store.Load(sp.SessionID())
		s.Status = types.SessionCompleted
		ss.store.Store(sp.SessionID(), s)
		_, err = ss.SigningSessionStatus(ctx, sp.SessionID())

		assert.EqualError(t, err, "failed to create VerifiablePresentation: error")
	})
}

type mockContext struct {
	ctrl     *gomock.Controller
	vcr      *vcr.MockVCR
	wallet   *holder.MockWallet
	issuer   *issuer.MockIssuer
	verifier *verifier.MockVerifier
}

func newMockContext(t *testing.T) mockContext {
	ctrl := gomock.NewController(t)

	mockVCR := vcr.NewMockVCR(ctrl)
	mockHolder := holder.NewMockWallet(ctrl)
	mockIssuer := issuer.NewMockIssuer(ctrl)
	mockVerifier := verifier.NewMockVerifier(ctrl)

	mockVCR.EXPECT().Wallet().Return(mockHolder).AnyTimes()
	mockVCR.EXPECT().Issuer().Return(mockIssuer).AnyTimes()
	mockVCR.EXPECT().Verifier().Return(mockVerifier).AnyTimes()

	return mockContext{
		ctrl:     ctrl,
		vcr:      mockVCR,
		issuer:   mockIssuer,
		wallet:   mockHolder,
		verifier: mockVerifier,
	}
}
