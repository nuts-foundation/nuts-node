/*
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
 *
 */

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery/api/server/client"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestModule_Name(t *testing.T) {
	assert.Equal(t, "Discovery", (&Module{}).Name())
}

func TestModule_Shutdown(t *testing.T) {
	m, _ := setupModule(t, storage.NewTestStorageEngine(t))
	require.NoError(t, m.Shutdown())
}

func Test_Module_Register(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	ctx := context.Background()

	t.Run("registration", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			m, testContext := setupModule(t, storageEngine, func(module *Module) {
				module.config.Client.RefreshInterval = 0
			})
			testContext.verifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil).Times(2)

			err := m.Register(ctx, testServiceID, vpAlice)
			require.NoError(t, err)

			_, seed, timestamp, err := m.Get(ctx, testServiceID, 0)
			require.NoError(t, err)
			assert.Equal(t, 1, timestamp)
			assert.NotEmpty(t, seed)

			t.Run("already exists", func(t *testing.T) {
				err = m.Register(ctx, testServiceID, vpAlice)

				assert.ErrorIs(t, err, ErrPresentationAlreadyExists)
			})
		})
		t.Run("not a server", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine, func(module *Module) {
				module.allDefinitions["someother"] = ServiceDefinition{
					ID:       "someother",
					Endpoint: "https://example.com/someother",
				}
				mockhttpclient := module.httpClient.(*client.MockHTTPClient)
				mockhttpclient.EXPECT().Get(gomock.Any(), "https://example.com/someother", gomock.Any()).Return(nil, testSeed, 0, nil).AnyTimes()
				mockhttpclient.EXPECT().Register(gomock.Any(), "https://example.com/someother", vpAlice).Return(nil)
			})

			err := m.Register(ctx, "someother", vpAlice)

			assert.NoError(t, err)
		})
		t.Run("VP verification fails (e.g. invalid signature)", func(t *testing.T) {
			m, testContext := setupModule(t, storageEngine)
			testContext.verifier.EXPECT().VerifyVP(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))

			err := m.Register(ctx, testServiceID, vpAlice)
			require.EqualError(t, err, "presentation is invalid for registration\npresentation verification failed: failed")

			_, _, timestamp, err := m.Get(ctx, testServiceID, 0)
			require.NoError(t, err)
			assert.Equal(t, 0, timestamp)
		})
		t.Run("valid for too long", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine, func(module *Module) {
				def := module.allDefinitions[testServiceID]
				def.PresentationMaxValidity = 1
				module.allDefinitions[testServiceID] = def
			})

			err := m.Register(ctx, testServiceID, vpAlice)

			assert.EqualError(t, err, "presentation is invalid for registration\npresentation is valid for too long (max 1s)")
		})
		t.Run("no expiration", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			err := m.Register(ctx, testServiceID, createPresentationCustom(aliceDID, func(claims map[string]interface{}, _ *vc.VerifiablePresentation) {
				claims[jwt.AudienceKey] = []string{testServiceID}
				delete(claims, "exp")
			}))
			assert.ErrorIs(t, err, errPresentationWithoutExpiration)
		})
		t.Run("presentation does not contain an ID", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)

			vpWithoutID := createPresentationCustom(aliceDID, func(claims map[string]interface{}, _ *vc.VerifiablePresentation) {
				claims[jwt.AudienceKey] = []string{testServiceID}
				delete(claims, "jti")
			}, vcAlice)
			err := m.Register(ctx, testServiceID, vpWithoutID)
			assert.ErrorIs(t, err, errPresentationWithoutID)
		})
		t.Run("not a JWT", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			err := m.Register(ctx, testServiceID, vc.VerifiablePresentation{})
			assert.ErrorIs(t, err, errUnsupportedPresentationFormat)
		})
		t.Run("valid longer than its credentials", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)

			vcAlice := createCredential(authorityDID, aliceDID, nil, func(claims map[string]interface{}) {
				claims[jwt.AudienceKey] = []string{testServiceID}
				claims["exp"] = time.Now().Add(time.Hour)
			})
			vpAlice := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				claims[jwt.AudienceKey] = []string{testServiceID}
			}, vcAlice)
			err := m.Register(ctx, testServiceID, vpAlice)
			assert.ErrorIs(t, err, errPresentationValidityExceedsCredentials)
		})
		t.Run("not conform to Presentation Definition", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)

			otherVP := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				claims[jwt.AudienceKey] = []string{testServiceID}
			}, createCredential(unsupportedDID, unsupportedDID, nil, nil))
			err := m.Register(ctx, testServiceID, otherVP)
			assert.ErrorIs(t, err, pe.ErrNoCredentials)

			_, _, timestamp, _ := m.Get(ctx, testServiceID, 0)
			assert.Equal(t, 0, timestamp)
		})
		t.Run("unsupported DID method", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine, func(module *Module) {
				module.serverDefinitions[unsupportedServiceID] = ServiceDefinition{
					ID:         unsupportedServiceID,
					DIDMethods: []string{"unsupported"},
				}
			})
			otherVP := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				claims[jwt.AudienceKey] = []string{unsupportedServiceID}
			}, vcAlice, aliceDiscoveryCredential)

			err := m.Register(ctx, unsupportedServiceID, otherVP)
			assert.ErrorIs(t, err, ErrDIDMethodsNotSupported)
		})
		t.Run("cycle detected", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine, func(module *Module) {
				module.allDefinitions["someother"] = ServiceDefinition{
					ID:       "someother",
					Endpoint: "https://example.com/someother",
				}
				mockhttpclient := module.httpClient.(*client.MockHTTPClient)
				mockhttpclient.EXPECT().Get(gomock.Any(), "https://example.com/someother", gomock.Any()).Return(nil, testSeed, 0, nil).AnyTimes()
			})
			ctx := context.WithValue(ctx, XForwardedHostContextKey{}, "https://example.com")

			err := m.Register(ctx, "someother", vc.VerifiablePresentation{})

			assert.ErrorIs(t, err, errCyclicForwardingDetected)
		})
	})
	t.Run("retraction", func(t *testing.T) {
		vpAliceRetract := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
			vp.Type = append(vp.Type, retractionPresentationType)
			claims["retract_jti"] = vpAlice.ID.String()
			claims[jwt.AudienceKey] = []string{testServiceID}
		})
		t.Run("ok", func(t *testing.T) {
			m, testContext := setupModule(t, storageEngine, func(module *Module) {
				// disable updater
				module.config.Client.RefreshInterval = 0
			})
			testContext.verifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil).Times(2)

			err := m.Register(ctx, testServiceID, vpAlice)
			require.NoError(t, err)
			err = m.Register(ctx, testServiceID, vpAliceRetract)
			assert.NoError(t, err)
		})
		t.Run("non-existent presentation", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			err := m.Register(ctx, testServiceID, vpAliceRetract)
			assert.ErrorIs(t, err, errRetractionReferencesUnknownPresentation)
		})
		t.Run("must not contain credentials", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
				claims[jwt.AudienceKey] = []string{testServiceID}
			}, vcAlice)
			err := m.Register(ctx, testServiceID, vp)
			assert.ErrorIs(t, err, errRetractionContainsCredentials)
		})
		t.Run("missing 'retract_jti' claim", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
				claims[jwt.AudienceKey] = []string{testServiceID}
			})
			err := m.Register(ctx, testServiceID, vp)
			assert.ErrorIs(t, err, errInvalidRetractionJTIClaim)
		})
		t.Run("'retract_jti' claim is not a string", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
				claims["retract_jti"] = 10
				claims[jwt.AudienceKey] = []string{testServiceID}
			})
			err := m.Register(ctx, testServiceID, vp)
			assert.ErrorIs(t, err, errInvalidRetractionJTIClaim)
		})
		t.Run("'retract_jti' claim is an empty string", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
				claims["retract_jti"] = ""
				claims[jwt.AudienceKey] = []string{testServiceID}
			})
			err := m.Register(ctx, testServiceID, vp)
			assert.ErrorIs(t, err, errInvalidRetractionJTIClaim)
		})
	})
}

func Test_Module_Get(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine, func(module *Module) {
			module.config.Client.RefreshInterval = 0
		})
		_, err := m.store.add(testServiceID, vpAlice, testSeed, 1)
		require.NoError(t, err)
		presentations, seed, timestamp, err := m.Get(ctx, testServiceID, 0)
		assert.NoError(t, err)
		assert.Equal(t, map[string]vc.VerifiablePresentation{"1": vpAlice}, presentations)
		assert.Equal(t, 1, timestamp)
		assert.NotEmpty(t, seed)

		t.Run("ok - retrieve delta", func(t *testing.T) {
			presentations, _, _, err := m.Get(ctx, testServiceID, 1)
			require.NoError(t, err)
			require.Len(t, presentations, 0)
		})
	})
	t.Run("not a server for this service ID, call forwarded", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine, func(module *Module) {
			module.allDefinitions["someother"] = ServiceDefinition{
				ID:       "someother",
				Endpoint: "https://example.com/someother",
			}
			mockhttpclient := module.httpClient.(*client.MockHTTPClient)
			mockhttpclient.EXPECT().Get(gomock.Any(), "https://example.com/someother", 0).Return(map[string]vc.VerifiablePresentation{"1": vpAlice}, "otherSeed", 1, nil).AnyTimes()
		})

		presentations, seed, timestamp, err := m.Get(ctx, "someother", 0)

		require.NoError(t, err)
		assert.Equal(t, 1, timestamp)
		assert.Len(t, presentations, 1)
		assert.Equal(t, "otherSeed", seed)
	})
	t.Run("not a server for this service ID, call forwarded, cycle detected", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine, func(module *Module) {
			module.allDefinitions["someother"] = ServiceDefinition{
				ID:       "someother",
				Endpoint: "https://example.com/someother",
			}
			mockhttpclient := module.httpClient.(*client.MockHTTPClient)
			mockhttpclient.EXPECT().Get(gomock.Any(), "https://example.com/someother", 0).Return(nil, "", 0, nil).AnyTimes()
		})
		ctx := context.WithValue(ctx, XForwardedHostContextKey{}, "https://example.com")

		_, _, _, err := m.Get(ctx, "someother", 0)

		assert.ErrorIs(t, err, errCyclicForwardingDetected)
	})
}

type mockContext struct {
	ctrl           *gomock.Controller
	subjectManager *didsubject.MockManager
	verifier       *verifier.MockVerifier
	didResolver    *resolver.MockDIDResolver
}

func setupModule(t *testing.T, storageInstance storage.Engine, visitors ...func(module *Module)) (*Module, mockContext) {
	resetStore(t, storageInstance.GetSQLDatabase())
	ctrl := gomock.NewController(t)
	mockVerifier := verifier.NewMockVerifier(ctrl)
	mockVCR := vcr.NewMockVCR(ctrl)
	mockVCR.EXPECT().Verifier().Return(mockVerifier).AnyTimes()
	mockSubjectManager := didsubject.NewMockManager(ctrl)
	mockDIDResolver := resolver.NewMockDIDResolver(ctrl)
	m := New(storageInstance, mockVCR, mockSubjectManager, mockDIDResolver)
	m.config = DefaultConfig()
	m.publicURL = test.MustParseURL("https://example.com")
	require.NoError(t, m.Configure(core.TestServerConfig()))

	httpClient := client.NewMockHTTPClient(ctrl)
	httpClient.EXPECT().Get(gomock.Any(), "http://example.com/other", gomock.Any()).Return(nil, testSeed, 0, nil).AnyTimes()
	httpClient.EXPECT().Get(gomock.Any(), "http://example.com/usecase", gomock.Any()).Return(nil, testSeed, 0, nil).AnyTimes()
	httpClient.EXPECT().Get(gomock.Any(), "http://example.com/unsupported", gomock.Any()).Return(nil, testSeed, 0, nil).AnyTimes()
	// set seed in DB otherwise behaviour is unpredictable due to background processes
	if m.store != nil {
		require.NoError(t, m.store.db.Transaction(func(tx *gorm.DB) error {
			service := serviceRecord{
				ID:                   testServiceID,
				Seed:                 testSeed,
				LastLamportTimestamp: 0,
			}
			return tx.Save(&service).Error
		}))
	}

	m.httpClient = httpClient
	m.allDefinitions = testDefinitions()
	m.serverDefinitions = map[string]ServiceDefinition{
		testServiceID: m.allDefinitions[testServiceID],
	}

	for _, visitor := range visitors {
		visitor(m)
	}

	require.NoError(t, m.Start())
	t.Cleanup(func() {
		_ = m.Shutdown()
	})
	return m, mockContext{
		ctrl:           ctrl,
		verifier:       mockVerifier,
		subjectManager: mockSubjectManager,
		didResolver:    mockDIDResolver,
	}
}

func TestModule_Configure(t *testing.T) {
	serverConfig := core.ServerConfig{
		URL: "https://example.com",
	}
	t.Run("missing publicURL", func(t *testing.T) {
		config := Config{
			Definitions: ServiceDefinitionsConfig{
				Directory: "test/duplicate_id",
			},
		}
		err := (&Module{config: config}).Configure(core.ServerConfig{})
		assert.EqualError(t, err, "'url' must be configured")
	})
	t.Run("duplicate ID", func(t *testing.T) {
		config := Config{
			Definitions: ServiceDefinitionsConfig{
				Directory: "test/duplicate_id",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.EqualError(t, err, "duplicate service definition ID 'urn:nuts.nl:usecase:eOverdrachtDev2023' in file 'test/duplicate_id/2.json'")
	})
	t.Run("invalid JSON", func(t *testing.T) {
		config := Config{
			Definitions: ServiceDefinitionsConfig{
				Directory: "test/invalid_json",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.ErrorContains(t, err, "unable to parse service definition file 'test/invalid_json/1.json'")
	})
	t.Run("invalid service definition", func(t *testing.T) {
		config := Config{
			Definitions: ServiceDefinitionsConfig{
				Directory: "test/invalid_definition",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.ErrorContains(t, err, "unable to parse service definition file 'test/invalid_definition/1.json'")
	})
	t.Run("non-existent directory 1", func(t *testing.T) {
		config := Config{
			Definitions: ServiceDefinitionsConfig{
				Directory: "test/non_existent",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.ErrorContains(t, err, "failed to load discovery defintions: stat test/non_existent: no such file or directory")
	})
	t.Run("non-existent directory 2", func(t *testing.T) {
		config := Config{
			Definitions: ServiceDefinitionsConfig{
				Directory: "test/non_existent",
			},
		}
		_, err := loadDefinitions(config.Definitions.Directory)
		assert.ErrorContains(t, err, "unable to read definitions directory 'test/non_existent'")
	})
	t.Run("missing definitions directory", func(t *testing.T) {
		config := Config{}
		m := &Module{config: config}
		err := m.Configure(serverConfig)

		require.NoError(t, err)
		assert.NotNil(t, m.publicURL)
		assert.NotNil(t, m.httpClient)
	})
}

func TestModule_Search(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Run("ok", func(t *testing.T) {
		m, ctx := setupModule(t, storageEngine, func(module *Module) {
			module.config.Client.RefreshInterval = 0
		})
		ctx.verifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil)
		_, err := m.store.add(testServiceID, vpAlice, testSeed, 1)
		require.NoError(t, err)
		require.NoError(t, m.registrationManager.validate())

		results, err := m.Search(testServiceID, map[string]string{
			"credentialSubject.person.givenName": "Alice",
		})
		assert.NoError(t, err)
		expectedJSON, _ := json.Marshal([]SearchResult{
			{
				Presentation: vpAlice,
				Fields: map[string]interface{}{
					"auth_server_url": "https://example.com/oauth2/alice",
					"issuer_field":    authorityDID,
				},
				Parameters: defaultRegistrationParams(aliceSubject),
			},
		})
		actualJSON, _ := json.Marshal(results)
		assert.JSONEq(t, string(expectedJSON), string(actualJSON))
	})
	t.Run("unknown service ID", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		_, err := m.Search("unknown", nil)
		assert.ErrorIs(t, err, ErrServiceNotFound)
	})
}

func TestModule_update(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	tests := []struct {
		name                  string
		refreshInterval       time.Duration
		expectedHTTPCalls     int
		expectedVerifyVPCalls int
	}{
		{
			name:                  "Start() initiates update",
			refreshInterval:       time.Millisecond,
			expectedHTTPCalls:     2,
			expectedVerifyVPCalls: 4,
		},
		{
			name:                  "update() runs on node startup",
			refreshInterval:       time.Hour,
			expectedHTTPCalls:     1,
			expectedVerifyVPCalls: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetStore(t, storageEngine.GetSQLDatabase())
			ctrl := gomock.NewController(t)
			mockVerifier := verifier.NewMockVerifier(ctrl)
			mockVCR := vcr.NewMockVCR(ctrl)
			mockVCR.EXPECT().Verifier().Return(mockVerifier).AnyTimes()
			m := New(storageEngine, mockVCR, nil, nil)
			m.config = DefaultConfig()
			m.publicURL = test.MustParseURL("https://example.com")
			m.config.Client.RefreshInterval = tt.refreshInterval
			require.NoError(t, m.Configure(core.TestServerConfig()))
			m.allDefinitions = testDefinitions()
			httpClient := client.NewMockHTTPClient(ctrl)
			httpWg := sync.WaitGroup{}
			httpWg.Add(tt.expectedHTTPCalls * len(m.allDefinitions))
			httpCounter := atomic.Int64{}
			httpCounter.Add(int64(tt.expectedHTTPCalls * len(m.allDefinitions)))
			httpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _, _ interface{}) (map[string]vc.VerifiablePresentation, string, int, error) {
				if httpCounter.Load() != int64(0) {
					httpWg.Done()
					httpCounter.Add(int64(-1))
				}
				return nil, testSeed, 0, nil
			}).MinTimes(tt.expectedHTTPCalls * len(m.allDefinitions))
			m.httpClient = httpClient
			m.store, _ = newSQLStore(m.storageInstance.GetSQLDatabase(), m.allDefinitions)
			vpWg := sync.WaitGroup{}
			vpWg.Add(tt.expectedVerifyVPCalls)
			vpCounter := atomic.Int64{}
			vpCounter.Add(int64(tt.expectedVerifyVPCalls))
			mockVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil).DoAndReturn(func(_, _, _, _ interface{}) ([]vc.VerifiableCredential, error) {
				if vpCounter.Load() != int64(0) {
					vpWg.Done()
					vpCounter.Add(int64(-1))
				}
				return nil, nil
			}).MinTimes(tt.expectedVerifyVPCalls)
			_, err := m.store.add(testServiceID, vpAlice, testSeed, 1)
			require.NoError(t, err)

			require.NoError(t, m.Start())

			vpWg.Wait()
			httpWg.Wait()

			t.Cleanup(func() {
				_ = m.Shutdown()
			})
		})
	}
}

func TestModule_ActivateServiceForSubject(t *testing.T) {
	t.Run("ok, syncs VPs immediately after registration", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		require.NoError(t, storageEngine.Start())
		m, testContext := setupModule(t, storageEngine, func(module *Module) {
			// overwrite httpClient mock for custom behavior assertions (we want to know how often HttpClient.Get() was called)
			httpClient := client.NewMockHTTPClient(gomock.NewController(t))
			httpClient.EXPECT().Register(gomock.Any(), gomock.Any(), vpAlice).Return(nil)
			httpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, "", 0, nil)
			module.httpClient = httpClient
			// disable auto-refresh job to have deterministic assertions
			module.config.Client.RefreshInterval = 0
		})
		// We expect the client to create 1 VP
		wallet := holder.NewMockWallet(gomock.NewController(t))
		m.vcrInstance.(*vcr.MockVCR).EXPECT().Wallet().Return(wallet).MinTimes(1)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{vcAlice}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&vpAlice, nil)
		testContext.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		testContext.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)

		err := m.ActivateServiceForSubject(context.Background(), testServiceID, aliceSubject, nil)

		assert.NoError(t, err)
	})
	t.Run("ok, with additional params", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		require.NoError(t, storageEngine.Start())
		m, testContext := setupModule(t, storageEngine, func(module *Module) {
			// overwrite httpClient mock for custom behavior assertions (we want to know how often HttpClient.Get() was called)
			httpClient := client.NewMockHTTPClient(gomock.NewController(t))
			httpClient.EXPECT().Register(gomock.Any(), gomock.Any(), vpAlice).Return(nil)
			httpClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, "", 0, nil)
			module.httpClient = httpClient
			// disable auto-refresh job to have deterministic assertions
			module.config.Client.RefreshInterval = 0
		})
		// We expect the client to create 1 VP
		wallet := holder.NewMockWallet(gomock.NewController(t))
		m.vcrInstance.(*vcr.MockVCR).EXPECT().Wallet().Return(wallet).MinTimes(1)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return([]vc.VerifiableCredential{vcAlice}, nil)
		wallet.EXPECT().BuildPresentation(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ interface{}, credentials []vc.VerifiableCredential, _ interface{}, _ interface{}, _ interface{}) (*vc.VerifiablePresentation, error) {
			// check if two credentials are given
			// check if the DiscoveryRegistrationCredential is added with a test value
			assert.Len(t, credentials, 2)
			subject := make([]credential.DiscoveryRegistrationCredentialSubject, 0)
			_ = credentials[1].UnmarshalCredentialSubject(&subject)
			assert.Equal(t, "value", subject[0]["test"])
			assert.Equal(t, "https://nuts.nl/oauth2/alice", subject[0]["authServerURL"])
			return &vpAlice, nil
		})
		testContext.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		testContext.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)

		err := m.ActivateServiceForSubject(context.Background(), testServiceID, aliceSubject, map[string]interface{}{"test": "value"})

		assert.NoError(t, err)
	})
	t.Run("not owned", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		require.NoError(t, storageEngine.Start())
		m, testContext := setupModule(t, storageEngine)
		testContext.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return(nil, didsubject.ErrSubjectNotFound)

		err := m.ActivateServiceForSubject(context.Background(), testServiceID, aliceSubject, nil)

		require.EqualError(t, err, "subject not found")
	})
	t.Run("deactivated DID", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		require.NoError(t, storageEngine.Start())
		m, testContext := setupModule(t, storageEngine)
		testContext.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		testContext.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, resolver.ErrDeactivated)

		err := m.ActivateServiceForSubject(context.Background(), testServiceID, aliceSubject, nil)

		assert.ErrorIs(t, err, ErrDIDMethodsNotSupported)
	})
	t.Run("ok, but couldn't register presentation -> maps to ErrRegistrationFailed", func(t *testing.T) {
		storageEngine := storage.NewTestStorageEngine(t)
		require.NoError(t, storageEngine.Start())
		m, testContext := setupModule(t, storageEngine)
		wallet := holder.NewMockWallet(gomock.NewController(t))
		m.vcrInstance.(*vcr.MockVCR).EXPECT().Wallet().Return(wallet).MinTimes(1)
		wallet.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed")).MinTimes(1)
		testContext.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		testContext.didResolver.EXPECT().Resolve(aliceDID, gomock.Any()).Return(nil, nil, nil)

		err := m.ActivateServiceForSubject(context.Background(), testServiceID, aliceSubject, nil)

		require.ErrorIs(t, err, ErrPresentationRegistrationFailed)
	})
}

func TestModule_Services(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Run("ok", func(t *testing.T) {
		services := (&Module{
			allDefinitions: testDefinitions(),
		}).Services()
		assert.Len(t, services, 3)
	})
}

func TestModule_GetServiceActivation(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Run("not activated", func(t *testing.T) {
		m, ctx := setupModule(t, storageEngine)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)

		activated, presentation, err := m.GetServiceActivation(context.Background(), testServiceID, aliceSubject)

		require.NoError(t, err)
		assert.False(t, activated)
		assert.Nil(t, presentation)
	})
	t.Run("activated, no VP", func(t *testing.T) {
		m, ctx := setupModule(t, storageEngine)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil)
		next := time.Now()
		_ = m.store.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &next)

		activated, presentation, err := m.GetServiceActivation(context.Background(), testServiceID, aliceSubject)

		require.NoError(t, err)
		assert.True(t, activated)
		assert.Nil(t, presentation)
	})
	t.Run("activated, with VP", func(t *testing.T) {
		m, testContext := setupModule(t, storageEngine, func(module *Module) {
			module.config.Client.RefreshInterval = 0
		})
		testContext.subjectManager.EXPECT().ListDIDs(gomock.Any(), aliceSubject).Return([]did.DID{aliceDID}, nil).AnyTimes()
		next := time.Now()
		_ = m.store.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &next)
		_, err := m.store.add(testServiceID, vpAlice, testSeed, 1)
		require.NoError(t, err)

		activated, presentation, err := m.GetServiceActivation(context.Background(), testServiceID, aliceSubject)

		require.NoError(t, err)
		assert.True(t, activated)
		assert.NotNil(t, presentation)

		t.Run("with refresh error", func(t *testing.T) {
			_ = m.store.setPresentationRefreshError(testServiceID, aliceSubject, assert.AnError)

			activated, _, err = m.GetServiceActivation(context.Background(), testServiceID, aliceSubject)

			require.Error(t, err)
			assert.True(t, activated)
			assert.ErrorAs(t, err, &RegistrationRefreshError{})
		})
	})
	t.Run("service does not exist - 404", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)

		activated, presentation, err := m.GetServiceActivation(context.Background(), "unknown", "unknown")

		assert.ErrorIs(t, err, ErrServiceNotFound)
		assert.False(t, activated)
		assert.Nil(t, presentation)
	})
	t.Run("subject does not exist - 404", func(t *testing.T) {
		m, ctx := setupModule(t, storageEngine)
		ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), "unknown").Return(nil, didsubject.ErrSubjectNotFound)

		activated, presentation, err := m.GetServiceActivation(context.Background(), testServiceID, "unknown")

		assert.ErrorIs(t, err, didsubject.ErrSubjectNotFound)
		assert.False(t, activated)
		assert.Nil(t, presentation)
	})
}
