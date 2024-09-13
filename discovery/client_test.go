/*
 * Copyright (C) 2024 Nuts community
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

package discovery

import (
	"context"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/discovery/api/server/client"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
	"time"
)

func Test_defaultClientRegistrationManager_activate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("immediate registration", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), "http://example.com/usecase", vpAlice)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{vcAlice}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).DoAndReturn(func(_ interface{}, credentials []vc.VerifiableCredential, options holder.PresentationOptions, _ interface{}, _ interface{}) (*vc.VerifiablePresentation, error) {
			// check if two credentials are given
			// check if the DiscoveryRegistrationCredential is added with an authServerURL
			assert.Len(t, credentials, 2)
			subject := make([]credential.DiscoveryRegistrationCredentialSubject, 0)
			_ = credentials[1].UnmarshalCredentialSubject(&subject)
			assert.Equal(t, "https://example.com/oauth2/alice", subject[0][authServerURLField])
			assert.Equal(t, aliceDID.String(), options.Holder.String())
			return &vpAlice, nil
		})
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		err := manager.activate(audit.TestContext(), testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject))

		assert.NoError(t, err)
	})
	t.Run("registration fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("invoker error"))
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{vcAlice}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		err := manager.activate(audit.TestContext(), testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject))

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		assert.ErrorContains(t, err, "invoker error")
	})
	t.Run("no matching credentials", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		err := manager.activate(audit.TestContext(), testServiceID, aliceSubject, nil)

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		require.ErrorIs(t, err, errMissingCredential)
	})
	t.Run("subject with 2 DIDs, one registers and other fails", func(t *testing.T) {
		subjectDIDs := []did.DID{aliceDID, bobDID}
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), "http://example.com/usecase", vpAlice)
		wallet := holder.NewMockWallet(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return(subjectDIDs, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		// aliceDID registers
		wallet.EXPECT().List(gomock.Any(), aliceDID).Return([]vc.VerifiableCredential{vcAlice}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &aliceDID, false).Return(&vpAlice, nil)
		// bobDID has no credentials, so builds no presentation
		wallet.EXPECT().List(gomock.Any(), bobDID).Return(nil, nil)

		err := manager.activate(audit.TestContext(), testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject))

		assert.NoError(t, err)
	})
	t.Run("ok without credentials", func(t *testing.T) {
		emptyDefinition := map[string]ServiceDefinition{
			testServiceID: {
				ID:       testServiceID,
				Endpoint: "http://example.com/usecase",
				PresentationDefinition: pe.PresentationDefinition{
					InputDescriptors: []*pe.InputDescriptor{},
				},
				PresentationMaxValidity: int((24 * time.Hour).Seconds()),
			},
		}
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), "http://example.com/usecase", vpAlice)
		mockVCR := vcr.NewMockVCR(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), []vc.VerifiableCredential{}, gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(emptyDefinition, store, invoker, mockVCR, mockSubjectManager)

		err := manager.activate(audit.TestContext(), testServiceID, aliceSubject, nil)

		assert.NoError(t, err)
	})
	t.Run("unknown service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, nil)

		err := manager.activate(audit.TestContext(), "unknown", aliceSubject, nil)

		assert.EqualError(t, err, "discovery service not found")
	})
	t.Run("unknown subject", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{}, didsubject.ErrSubjectNotFound)
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		err := manager.activate(audit.TestContext(), testServiceID, aliceSubject, nil)

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
}

func Test_defaultClientRegistrationManager_deactivate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("not registered", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.NoError(t, err)
	})
	t.Run("registered", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any())
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)
		require.NoError(t, store.add(testServiceID, vpAlice, 1))

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.NoError(t, err)
	})
	t.Run("already deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(holder.NewMockWallet(ctrl)).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		vpAliceDeactivated := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
			claims[jwt.AudienceKey] = []string{testServiceID}
			claims["retract_jti"] = vpAlice.ID.String()
			vp.Type = append(vp.Type, retractionPresentationType)
		}, vcAlice)
		require.NoError(t, store.add(testServiceID, vpAliceDeactivated, 1))

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.NoError(t, err)
	})
	t.Run("deregistering from Discovery Service fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("remote error"))
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)
		require.NoError(t, store.add(testServiceID, vpAlice, 1))

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		require.ErrorContains(t, err, "remote error")
	})
	t.Run("building presentation fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(nil, assert.AnError)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)
		require.NoError(t, store.add(testServiceID, vpAlice, 1))

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.ErrorIs(t, err, assert.AnError)
	})
	t.Run("unknown subject", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{}, didsubject.ErrSubjectNotFound)
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
}

func Test_defaultClientRegistrationManager_refresh(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("no registrations", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		err := manager.refresh(audit.TestContext(), time.Now())

		require.NoError(t, err)
	})
	t.Run("2 VPs to refresh, first one fails, second one succeeds", func(t *testing.T) {
		store := setupStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		gomock.InOrder(
			invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()),
			invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("remote error")),
		)
		wallet := holder.NewMockWallet(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)

		// Alice
		_ = store.updatePresentationRefreshTime(testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject), &time.Time{})
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &aliceDID, false).Return(&vpAlice, nil)
		wallet.EXPECT().List(gomock.Any(), aliceDID).Return([]vc.VerifiableCredential{vcAlice}, nil)
		// Bob
		_ = store.updatePresentationRefreshTime(testServiceID, bobSubject, defaultRegistrationParams(aliceSubject), &time.Time{})
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), bobSubject).Return([]did.DID{bobDID}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &bobDID, false).Return(&vpBob, nil)
		wallet.EXPECT().List(gomock.Any(), bobDID).Return([]vc.VerifiableCredential{vcBob}, nil)

		err := manager.refresh(audit.TestContext(), time.Now())

		assert.EqualError(t, err, "failed to refresh Verifiable Presentation (service=usecase_v1, subject=bob): registration of Verifiable Presentation on remote Discovery Service failed: did:example:bob: remote error")
	})
	t.Run("deactivate unknown subject", func(t *testing.T) {
		store := setupStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		mockSubjectManager := didsubject.NewMockSubjectManager(ctrl)
		mockSubjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return(nil, didsubject.ErrSubjectNotFound)
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR, mockSubjectManager)
		_ = store.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &time.Time{})

		err := manager.refresh(audit.TestContext(), time.Now())

		assert.EqualError(t, err, "removed unknown subject (service=usecase_v1, subject=alice)")
	})
}

func Test_clientUpdater_updateService(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	store, err := newSQLStore(storageEngine.GetSQLDatabase(), testDefinitions())
	require.NoError(t, err)
	ctx := context.Background()
	serviceDefinition := testDefinitions()[testServiceID]

	t.Run("no updates", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		httpClient.EXPECT().Get(ctx, testDefinitions()[testServiceID].Endpoint, 0).Return(map[string]vc.VerifiablePresentation{}, 0, nil)

		err := updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
	t.Run("updates", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, 0).Return(map[string]vc.VerifiablePresentation{"1": vpAlice}, 1, nil)

		err := updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
	t.Run("ignores invalid presentations", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, func(_ ServiceDefinition, vp vc.VerifiablePresentation) error {
			if *vp.ID == *vpAlice.ID {
				return errors.New("invalid presentation")
			}
			return nil
		}, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, 0).Return(map[string]vc.VerifiablePresentation{"1": vpAlice, "2": vpBob}, 2, nil)

		err := updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
		// Bob's VP should exist, Alice's not
		exists, err := store.exists(testServiceID, bobDID.String(), vpBob.ID.String())
		require.NoError(t, err)
		require.True(t, exists)
		exists, err = store.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		require.NoError(t, err)
		require.False(t, exists)
	})
	t.Run("pass timestamp", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		err := store.setTimestamp(store.db, testServiceID, 1)
		require.NoError(t, err)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, 1).Return(map[string]vc.VerifiablePresentation{"1": vpAlice}, 1, nil)

		err = updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
}

func Test_clientUpdater_update(t *testing.T) {
	t.Run("proceeds when service update fails", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		require.NoError(t, storageEngine.Start())
		store := setupStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Get(gomock.Any(), "http://example.com/usecase", gomock.Any()).Return(map[string]vc.VerifiablePresentation{}, 0, nil)
		httpClient.EXPECT().Get(gomock.Any(), "http://example.com/other", gomock.Any()).Return(nil, 0, errors.New("test"))
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		err := updater.update(context.Background())

		require.EqualError(t, err, "failed to get presentations from discovery service (id=other): test")
	})
	t.Run("no error", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		require.NoError(t, storageEngine.Start())
		store := setupStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]vc.VerifiablePresentation{}, 0, nil).MinTimes(2)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		err := updater.update(context.Background())

		assert.NoError(t, err)
	})
}

func alwaysOkVerifier(_ ServiceDefinition, _ vc.VerifiablePresentation) error {
	return nil
}
