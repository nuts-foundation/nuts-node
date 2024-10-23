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
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
	"time"
)

var nextRefresh = time.Now().Add(-1 * time.Hour)

type testContext struct {
	ctrl           *gomock.Controller
	didResolver    *resolver.MockDIDResolver
	invoker        *client.MockHTTPClient
	vcr            *vcr.MockVCR
	wallet         *holder.MockWallet
	subjectManager *didsubject.MockManager
	store          *sqlStore
	manager        *clientRegistrationManager
}

func newTestContext(t *testing.T) testContext {
	t.Helper()
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	ctrl := gomock.NewController(t)
	didResolver := resolver.NewMockDIDResolver(ctrl)
	invoker := client.NewMockHTTPClient(ctrl)
	vcr := vcr.NewMockVCR(ctrl)
	wallet := holder.NewMockWallet(ctrl)
	subjectManager := didsubject.NewMockManager(ctrl)
	store := setupStore(t, storageEngine.GetSQLDatabase())
	manager := newRegistrationManager(testDefinitions(), store, invoker, vcr, subjectManager, didResolver, alwaysOkVerifier)
	vcr.EXPECT().Wallet().Return(wallet).AnyTimes()

	return testContext{
		ctrl:           ctrl,
		didResolver:    didResolver,
		invoker:        invoker,
		vcr:            vcr,
		wallet:         wallet,
		subjectManager: subjectManager,
		store:          store,
		manager:        manager,
	}
}

func Test_defaultClientRegistrationManager_activate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("immediate registration", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.invoker.EXPECT().Register(gomock.Any(), "http://example.com/usecase", vpAlice)
		ctx.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{vcAlice}, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).DoAndReturn(func(_ interface{}, credentials []vc.VerifiableCredential, options holder.PresentationOptions, _ interface{}, _ interface{}) (*vc.VerifiablePresentation, error) {
			// check if two credentials are given
			// check if the DiscoveryRegistrationCredential is added with an authServerURL
			assert.Len(t, credentials, 2)
			subject := make([]credential.DiscoveryRegistrationCredentialSubject, 0)
			_ = credentials[1].UnmarshalCredentialSubject(&subject)
			assert.Equal(t, "https://example.com/oauth2/alice", subject[0][authServerURLField])
			assert.Equal(t, aliceDID.String(), options.Holder.String())
			return &vpAlice, nil
		})
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)

		err := ctx.manager.activate(audit.TestContext(), testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject))

		assert.NoError(t, err)
	})
	t.Run("registration fails", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("invoker error"))
		ctx.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{vcAlice}, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)

		err := ctx.manager.activate(audit.TestContext(), testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject))

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		assert.ErrorContains(t, err, "invoker error")

		// check no refresh records are added
		record, err := ctx.store.getPresentationRefreshRecord(testServiceID, aliceSubject)

		require.NoError(t, err)
		assert.Nil(t, record)
	})
	t.Run("DID method not supported", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)

		err := ctx.manager.activate(audit.TestContext(), unsupportedServiceID, aliceSubject, defaultRegistrationParams(aliceSubject))

		assert.ErrorIs(t, err, ErrDIDMethodsNotSupported)
	})
	t.Run("no matching credentials", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil)
		ctx.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)

		err := ctx.manager.activate(audit.TestContext(), testServiceID, aliceSubject, nil)

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		require.ErrorIs(t, err, pe.ErrNoCredentials)
	})
	t.Run("subject with 2 DIDs, one registers and other fails", func(t *testing.T) {
		ctx := newTestContext(t)
		subjectDIDs := []did.DID{aliceDID, bobDID}
		ctx.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)
		ctx.didResolver.EXPECT().Resolve(bobDID, gomock.Any()).Return(nil, nil, nil)
		ctx.invoker.EXPECT().Register(gomock.Any(), "http://example.com/usecase", vpAlice)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return(subjectDIDs, nil)

		// aliceDID registers
		ctx.wallet.EXPECT().List(gomock.Any(), aliceDID).Return([]vc.VerifiableCredential{vcAlice}, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &aliceDID, false).Return(&vpAlice, nil)
		// bobDID has no credentials, so builds no presentation
		ctx.wallet.EXPECT().List(gomock.Any(), bobDID).Return(nil, nil)

		err := ctx.manager.activate(audit.TestContext(), testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject))

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
		ctx := newTestContext(t)
		ctx.invoker.EXPECT().Register(gomock.Any(), "http://example.com/usecase", vpAlice)
		ctx.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).DoAndReturn(func(_ interface{}, credentials []vc.VerifiableCredential, _ interface{}, _ interface{}, _ interface{}) (*vc.VerifiablePresentation, error) {
			assert.Len(t, credentials, 0)
			return &vpAlice, nil
		})
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		ctx.manager = newRegistrationManager(emptyDefinition, ctx.store, ctx.invoker, ctx.vcr, ctx.subjectManager, ctx.didResolver, alwaysOkVerifier)

		err := ctx.manager.activate(audit.TestContext(), testServiceID, aliceSubject, nil)

		assert.NoError(t, err)
	})
	t.Run("unknown service", func(t *testing.T) {
		ctx := newTestContext(t)

		err := ctx.manager.activate(audit.TestContext(), "unknown", aliceSubject, nil)

		assert.EqualError(t, err, "discovery service not found")
	})
	t.Run("unknown subject", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{}, didsubject.ErrSubjectNotFound)

		err := ctx.manager.activate(audit.TestContext(), testServiceID, aliceSubject, nil)

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
}

func Test_defaultClientRegistrationManager_deactivate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("not registered", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)

		err := ctx.manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.NoError(t, err)
	})
	t.Run("registered", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any())
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).DoAndReturn(
			func(ctx context.Context, credentials []vc.VerifiableCredential, options holder.PresentationOptions, signerDID *did.DID, validateVC bool) (*vc.VerifiablePresentation, error) {
				assert.Equal(t, options.AdditionalTypes[0], retractionPresentationType)
				return &vpAlice, nil // not a revocation VP
			})
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		_, err := ctx.store.add(testServiceID, vpAlice, testSeed, 1)
		require.NoError(t, err)

		err = ctx.manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.NoError(t, err)
	})
	t.Run("already deactivated", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)

		vpAliceDeactivated := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
			claims[jwt.AudienceKey] = []string{testServiceID}
			claims["retract_jti"] = vpAlice.ID.String()
			vp.Type = append(vp.Type, retractionPresentationType)
		}, vcAlice)
		_, err := ctx.store.add(testServiceID, vpAliceDeactivated, testSeed, 1)
		require.NoError(t, err)

		err = ctx.manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.NoError(t, err)
	})
	t.Run("DID method not supported", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)

		err := ctx.manager.deactivate(audit.TestContext(), unsupportedServiceID, aliceSubject)

		assert.ErrorIs(t, err, ErrDIDMethodsNotSupported)
	})
	t.Run("deregistering from Discovery Service fails", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("remote error"))
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(&vpAlice, nil)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		_, err := ctx.store.add(testServiceID, vpAlice, testSeed, 1)
		require.NoError(t, err)

		err = ctx.manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
		require.ErrorContains(t, err, "remote error")
	})
	t.Run("building presentation fails", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), false).Return(nil, assert.AnError)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		_, err := ctx.store.add(testServiceID, vpAlice, testSeed, 1)
		require.NoError(t, err)

		err = ctx.manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.ErrorIs(t, err, assert.AnError)
	})
	t.Run("unknown subject", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{}, didsubject.ErrSubjectNotFound)

		err := ctx.manager.deactivate(audit.TestContext(), testServiceID, aliceSubject)

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
	})
	t.Run("unknown service", func(t *testing.T) {
		ctx := newTestContext(t)

		err := ctx.manager.deactivate(audit.TestContext(), "unknown", aliceSubject)

		assert.ErrorIs(t, err, ErrServiceNotFound)
	})
}

func Test_defaultClientRegistrationManager_refresh(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("no registrations", func(t *testing.T) {
		ctx := newTestContext(t)

		err := ctx.manager.refresh(audit.TestContext(), time.Now())

		require.NoError(t, err)
	})
	t.Run("2 VPs to refresh, first one fails, second one succeeds", func(t *testing.T) {
		ctx := newTestContext(t)
		gomock.InOrder(
			ctx.invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()),
			ctx.invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("remote error")),
		)
		gomock.InOrder(
			ctx.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil),
			ctx.didResolver.EXPECT().Resolve(bobDID, gomock.Any()).Return(nil, nil, nil),
		)

		// Alice
		_ = ctx.store.updatePresentationRefreshTime(testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject), &nextRefresh)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &aliceDID, false).Return(&vpAlice, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), aliceDID).Return([]vc.VerifiableCredential{vcAlice}, nil)
		// Bob
		_ = ctx.store.updatePresentationRefreshTime(testServiceID, bobSubject, defaultRegistrationParams(aliceSubject), &nextRefresh)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), bobSubject).Return([]did.DID{bobDID}, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &bobDID, false).Return(&vpBob, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), bobDID).Return([]vc.VerifiableCredential{vcBob}, nil)

		err := ctx.manager.refresh(audit.TestContext(), time.Now())

		errStr := "failed to refresh Verifiable Presentation (service=usecase_v1, subject=bob): registration of Verifiable Presentation on remote Discovery Service failed: did:example:bob: remote error"
		assert.EqualError(t, err, errStr)

		// check for presentationRefreshError
		refreshError := getPresentationRefreshError(t, ctx.store.db, testServiceID, bobSubject)
		assert.Contains(t, refreshError.Error, errStr)
	})
	t.Run("deactivate unknown subject", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return(nil, didsubject.ErrSubjectNotFound)
		_ = ctx.store.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &nextRefresh)

		err := ctx.manager.refresh(audit.TestContext(), time.Now())

		assert.EqualError(t, err, "removed unknown subject (service=usecase_v1, subject=alice)")
	})
	t.Run("deactivate unsupported DID method", func(t *testing.T) {
		ctx := newTestContext(t)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		ctx.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, resolver.ErrDeactivated)
		_ = ctx.store.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &nextRefresh)

		err := ctx.manager.refresh(audit.TestContext(), time.Now())

		// refresh clears the registration
		assert.EqualError(t, err, "removed subject that has no supported DID method (service=usecase_v1, subject=alice)")
		record, err := ctx.store.getPresentationRefreshRecord(testServiceID, aliceSubject)
		assert.NoError(t, err)
		assert.Nil(t, record)
	})
	t.Run("remove presentationRefreshError on success", func(t *testing.T) {
		ctx := newTestContext(t)
		gomock.InOrder(
			ctx.invoker.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()),
		)
		ctx.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)

		// Alice
		_ = ctx.store.setPresentationRefreshError(testServiceID, aliceSubject, assert.AnError)
		_ = ctx.store.updatePresentationRefreshTime(testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject), &time.Time{})
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), &aliceDID, false).Return(&vpAlice, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), aliceDID).Return([]vc.VerifiableCredential{vcAlice}, nil)

		err := ctx.manager.refresh(audit.TestContext(), time.Now())

		require.NoError(t, err)

		// check for presentationRefreshError
		refreshError := getPresentationRefreshError(t, ctx.store.db, testServiceID, aliceSubject)
		assert.Nil(t, refreshError)
	})
}

func Test_defaultClientRegistrationManager_validate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	tests := []struct {
		name         string
		setupManager func(ctx testContext) *clientRegistrationManager
		expectedLen  int
	}{
		{
			name: "ok",
			setupManager: func(ctx testContext) *clientRegistrationManager {
				return ctx.manager
			},
			expectedLen: 1,
		},
		{
			name: "verification failed",
			setupManager: func(ctx testContext) *clientRegistrationManager {
				return newRegistrationManager(testDefinitions(), ctx.store, ctx.invoker, ctx.vcr, ctx.subjectManager, ctx.didResolver, func(service ServiceDefinition, vp vc.VerifiablePresentation) error {
					return errors.New("verification failed")
				})
			},
			expectedLen: 0,
		},
		{
			name: "registration for unknown service",
			setupManager: func(ctx testContext) *clientRegistrationManager {
				return newRegistrationManager(map[string]ServiceDefinition{}, ctx.store, ctx.invoker, ctx.vcr, ctx.subjectManager, ctx.didResolver, alwaysOkVerifier)
			},
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestContext(t)
			_, err := ctx.store.add(testServiceID, vpAlice, testSeed, 1)
			require.NoError(t, err)
			manager := tt.setupManager(ctx)

			err = manager.validate()
			require.NoError(t, err)

			presentations, err := ctx.store.allPresentations(true)
			require.NoError(t, err)
			assert.Len(t, presentations, tt.expectedLen)
		})
	}
}

func Test_defaultClientRegistrationManager_removeRevoked(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	tests := []struct {
		name          string
		verifyVPError error
		expectedLen   int
	}{
		{
			name:          "ok - not revoked",
			verifyVPError: nil,
			expectedLen:   1,
		},
		{
			name:          "ok - revoked",
			verifyVPError: types.ErrRevoked,
			expectedLen:   0,
		},
		{
			name:          "error",
			verifyVPError: assert.AnError,
			expectedLen:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTestContext(t)
			_, err := ctx.store.add(testServiceID, vpAlice, testSeed, 1)
			require.NoError(t, err)
			require.NoError(t, ctx.manager.validate())

			mockVerifier := verifier.NewMockVerifier(ctx.ctrl)
			ctx.vcr.EXPECT().Verifier().Return(mockVerifier).AnyTimes()
			mockVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil).Return(nil, tt.verifyVPError)

			err = ctx.manager.removeRevoked()
			require.NoError(t, err)

			presentations, err := ctx.store.allPresentations(true)
			require.NoError(t, err)
			assert.Len(t, presentations, tt.expectedLen)
		})
	}
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

		httpClient.EXPECT().Get(ctx, testDefinitions()[testServiceID].Endpoint, 0).Return(map[string]vc.VerifiablePresentation{}, testSeed, 0, nil)

		err := updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
	t.Run("updates", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, 0).Return(map[string]vc.VerifiablePresentation{"1": vpAlice}, testSeed, 1, nil)

		require.NoError(t, updater.updateService(ctx, testDefinitions()[testServiceID]))

		t.Run("ignores duplicates", func(t *testing.T) {
			httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, 1).Return(map[string]vc.VerifiablePresentation{"1": vpAlice}, testSeed, 1, nil)

			require.NoError(t, updater.updateService(ctx, testDefinitions()[testServiceID]))

			// check count
			presentation, err := updater.store.allPresentations(true)

			require.NoError(t, err)
			assert.Len(t, presentation, 1)
		})
	})
	t.Run("allows invalid presentations", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, func(_ ServiceDefinition, vp vc.VerifiablePresentation) error {
			if *vp.ID == *vpAlice.ID {
				return errors.New("invalid presentation")
			}
			return nil
		}, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, 0).Return(map[string]vc.VerifiablePresentation{"1": vpAlice, "2": vpBob}, testSeed, 2, nil)

		err := updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
		// Both should exist, 1 should be validated immediately
		exists, err := store.exists(testServiceID, bobDID.String(), vpBob.ID.String())
		require.NoError(t, err)
		require.True(t, exists)
		exists, err = store.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		require.NoError(t, err)
		require.True(t, exists)
		validated, err := store.allPresentations(true)
		require.NoError(t, err)
		require.Len(t, validated, 1)
	})
	t.Run("pass timestamp", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		err := store.setTimestamp(store.db, testServiceID, testSeed, 1)
		require.NoError(t, err)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		httpClient.EXPECT().Get(ctx, serviceDefinition.Endpoint, 1).Return(map[string]vc.VerifiablePresentation{"1": vpAlice}, testSeed, 1, nil)

		err = updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
	})
	t.Run("seed change wipes entries", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)
		store.add(testServiceID, vpAlice, testSeed, 0)

		exists, err := store.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		require.NoError(t, err)
		require.True(t, exists)

		httpClient.EXPECT().Get(ctx, testDefinitions()[testServiceID].Endpoint, 1).Return(map[string]vc.VerifiablePresentation{}, "other", 0, nil)

		err = updater.updateService(ctx, testDefinitions()[testServiceID])

		require.NoError(t, err)
		exists, err = store.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		require.NoError(t, err)
		require.False(t, exists)
	})
}

func Test_clientUpdater_update(t *testing.T) {
	seed := "seed"
	t.Run("proceeds when service update fails", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		require.NoError(t, storageEngine.Start())
		store := setupStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		httpClient := client.NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Get(gomock.Any(), "http://example.com/usecase", gomock.Any()).Return(map[string]vc.VerifiablePresentation{}, seed, 0, nil)
		httpClient.EXPECT().Get(gomock.Any(), "http://example.com/other", gomock.Any()).Return(nil, "", 0, errors.New("test"))
		httpClient.EXPECT().Get(gomock.Any(), "http://example.com/unsupported", gomock.Any()).Return(map[string]vc.VerifiablePresentation{}, seed, 0, nil)
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
		httpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]vc.VerifiablePresentation{}, seed, 0, nil).MinTimes(2)
		updater := newClientUpdater(testDefinitions(), store, alwaysOkVerifier, httpClient)

		err := updater.update(context.Background())

		assert.NoError(t, err)
	})
}

func alwaysOkVerifier(_ ServiceDefinition, _ vc.VerifiablePresentation) error {
	return nil
}
