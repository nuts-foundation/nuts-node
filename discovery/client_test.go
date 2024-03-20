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
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/discovery/api/v1/client"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
	"time"
)

func Test_scheduledRegistrationManager_register(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("immediate registration", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), "http://example.com/usecase", vpAlice)
		mockVCR := vcr.NewMockVCR(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{vcAlice}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), []vc.VerifiableCredential{vcAlice}, gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)

		err := manager.activate(audit.TestContext(), testServiceID, aliceDID)

		assert.NoError(t, err)
	})
	t.Run("registration fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("invoker error"))
		mockVCR := vcr.NewMockVCR(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{vcAlice}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)

		err := manager.activate(audit.TestContext(), testServiceID, aliceDID)

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		assert.ErrorContains(t, err, "invoker error")
	})
	t.Run("no matching credentials", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)

		err := manager.activate(audit.TestContext(), testServiceID, aliceDID)

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		assert.ErrorContains(t, err, "DID wallet does not have credentials required for registration on Discovery Service (service=usecase_v1, did=did:example:alice)")
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
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(emptyDefinition, store, invoker, mockVCR)

		err := manager.activate(audit.TestContext(), testServiceID, aliceDID)

		assert.NoError(t, err)
	})
	t.Run("unknown service", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)

		err := manager.activate(audit.TestContext(), "unknown", aliceDID)

		assert.EqualError(t, err, "discovery service not found")
	})
}

func Test_scheduledRegistrationManager_deregister(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("not registered", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceDID)

		assert.NoError(t, err)
	})
	t.Run("registered", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any())
		mockVCR := vcr.NewMockVCR(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)
		require.NoError(t, store.add(testServiceID, vpAlice, "taggy"))

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceDID)

		assert.NoError(t, err)
	})
	t.Run("deregistering from Discovery Service fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("remote error"))
		mockVCR := vcr.NewMockVCR(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)
		require.NoError(t, store.add(testServiceID, vpAlice, "taggy"))

		err := manager.deactivate(audit.TestContext(), testServiceID, aliceDID)

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		require.ErrorContains(t, err, "remote error")
	})
}

func Test_scheduledRegistrationManager_refresh(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("no registrations", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		mockVCR := vcr.NewMockVCR(ctrl)
		store := setupStore(t, storageEngine.GetSQLDatabase())
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)

		err := manager.refresh(audit.TestContext(), time.Now())

		require.NoError(t, err)
	})
	t.Run("2 VPs to refresh, first one fails, second one succeeds", func(t *testing.T) {
		store := setupStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		invoker := client.NewMockHTTPClient(ctrl)
		gomock.InOrder(
			invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("remote error")),
			invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()),
		)
		mockVCR := vcr.NewMockVCR(ctrl)
		wallet := holder.NewMockWallet(ctrl)
		mockVCR.EXPECT().Wallet().Return(wallet).AnyTimes()
		manager := newRegistrationManager(testDefinitions(), store, invoker, mockVCR)
		// Alice
		_ = store.updatePresentationRefreshTime(testServiceID, aliceDID, &time.Time{})
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &aliceDID, false).Return(&vpAlice, nil)
		wallet.EXPECT().List(gomock.Any(), aliceDID).Return([]vc.VerifiableCredential{vcAlice}, nil)
		// Bob
		_ = store.updatePresentationRefreshTime(testServiceID, bobDID, &time.Time{})
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &bobDID, false).Return(&vpBob, nil)
		wallet.EXPECT().List(gomock.Any(), bobDID).Return([]vc.VerifiableCredential{vcBob}, nil)

		err := manager.refresh(audit.TestContext(), time.Now())

		assert.EqualError(t, err, "failed to refresh Verifiable Presentation (service=usecase_v1, did=did:example:alice): registration of Verifiable Presentation on remote Discovery Service failed: remote error")
	})
}

func Test_clientUpdater_updateService(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	store, err := newSQLStore(storageEngine.GetSQLDatabase(), testDefinitions(), nil)
	require.NoError(t, err)
	ctx := context.Background()
	newTag := "test"
	serviceDefinition := testDefinitions()[testServiceID]

	t.Run("no updates", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		httpClient.EXPECT().Get(ctx, testDefinitions()[testServiceID].Endpoint, "").Return([]vc.VerifiablePresentation{}, newTag, nil)

		err := updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
	t.Run("updates", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, "").Return([]vc.VerifiablePresentation{vpAlice}, newTag, nil)

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

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, "").Return([]vc.VerifiablePresentation{vpAlice, vpBob}, newTag, nil)

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
	t.Run("pass tag", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		_, err := store.updateTag(store.db, testServiceID, "test")
		require.NoError(t, err)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, "test").Return([]vc.VerifiablePresentation{vpAlice}, newTag, nil)

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
		httpClient.EXPECT().Get(gomock.Any(), "http://example.com/usecase", gomock.Any()).Return([]vc.VerifiablePresentation{}, "test", nil)
		httpClient.EXPECT().Get(gomock.Any(), "http://example.com/other", gomock.Any()).Return(nil, "", errors.New("test"))
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
		httpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return([]vc.VerifiablePresentation{}, "test", nil).MinTimes(2)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		err := updater.update(context.Background())

		assert.NoError(t, err)
	})
}

func alwaysOkVerifier(_ ServiceDefinition, _ vc.VerifiablePresentation) error {
	return nil
}
