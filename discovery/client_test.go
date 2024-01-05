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
	"github.com/nuts-foundation/nuts-node/discovery/api/v1/client"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"sync"
	"testing"
	"time"
)

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
		verifier := NewMockregistrationVerifier(ctrl)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, verifier, httpClient)

		httpClient.EXPECT().Get(ctx, testDefinitions()[testServiceID].Endpoint, nil).Return([]vc.VerifiablePresentation{}, &newTag, nil)

		err := updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
	t.Run("updates", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		verifier := NewMockregistrationVerifier(ctrl)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, verifier, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, nil).Return([]vc.VerifiablePresentation{vpAlice}, &newTag, nil)
		verifier.EXPECT().verifyRegistration(serviceDefinition, vpAlice).Return(nil)

		err := updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
	t.Run("ignores invalid presentations", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		verifier := NewMockregistrationVerifier(ctrl)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, verifier, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, nil).Return([]vc.VerifiablePresentation{vpAlice, vpBob}, &newTag, nil)
		verifier.EXPECT().verifyRegistration(serviceDefinition, vpAlice).Return(errors.New("invalid presentation"))
		verifier.EXPECT().verifyRegistration(serviceDefinition, vpBob).Return(nil)

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
		verifier := NewMockregistrationVerifier(ctrl)
		httpClient := client.NewMockHTTPClient(ctrl)
		inputTag := Tag("test")
		_, err := store.updateTag(store.db, testServiceID, &inputTag)
		require.NoError(t, err)
		updater := newClientUpdater(testDefinitions(), store, verifier, httpClient)

		clientTagStr := string(inputTag)
		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, gomock.Eq(&clientTagStr)).Return([]vc.VerifiablePresentation{vpAlice}, &newTag, nil)
		verifier.EXPECT().verifyRegistration(serviceDefinition, vpAlice).Return(nil)

		err = updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
}

func Test_clientUpdater_update(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("context cancel stops the loop", func(t *testing.T) {
		store := setupStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		verifier := NewMockregistrationVerifier(ctrl)
		httpClient := client.NewMockHTTPClient(ctrl)
		newTag := "test"
		httpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return([]vc.VerifiablePresentation{}, &newTag, nil).MinTimes(1)
		updater := newClientUpdater(testDefinitions(), store, verifier, httpClient)

		ctx, cancel := context.WithCancel(context.Background())
		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			updater.update(ctx, time.Millisecond)
		}()
		// make sure the loop has at least once
		time.Sleep(5 * time.Millisecond)
		// Make sure the function exits when the context is cancelled
		cancel()
		wg.Wait()
	})
}
