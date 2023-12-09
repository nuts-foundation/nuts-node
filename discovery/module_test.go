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
	"errors"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
	"time"
)

func TestModule_Name(t *testing.T) {
	assert.Equal(t, "Discovery", (&Module{}).Name())
}

func TestModule_Shutdown(t *testing.T) {
	assert.NoError(t, (&Module{}).Shutdown())
}

func Test_Module_Add(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("not a server", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)

		err := m.Add("other", vpAlice)
		require.EqualError(t, err, "node is not a discovery server for this service")
	})
	t.Run("VP verification fails (e.g. invalid signature)", func(t *testing.T) {
		m, presentationVerifier := setupModule(t, storageEngine)
		presentationVerifier.EXPECT().VerifyVP(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))

		err := m.Add(testServiceID, vpAlice)
		require.EqualError(t, err, "presentation is invalid for registration\npresentation verification failed: failed")

		_, tag, err := m.Get(testServiceID, nil)
		require.NoError(t, err)
		expectedTag := tagForTimestamp(t, m.store, testServiceID, 0)
		assert.Equal(t, expectedTag, *tag)
	})
	t.Run("already exists", func(t *testing.T) {
		m, presentationVerifier := setupModule(t, storageEngine)
		presentationVerifier.EXPECT().VerifyVP(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := m.Add(testServiceID, vpAlice)
		assert.NoError(t, err)
		err = m.Add(testServiceID, vpAlice)
		assert.ErrorIs(t, err, ErrPresentationAlreadyExists)
	})
	t.Run("valid for too long", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		def := m.services[testServiceID]
		def.PresentationMaxValidity = 1
		m.services[testServiceID] = def
		m.serverDefinitions[testServiceID] = def

		err := m.Add(testServiceID, vpAlice)
		assert.EqualError(t, err, "presentation is invalid for registration\npresentation is valid for too long (max 1s)")
	})
	t.Run("no expiration", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		err := m.Add(testServiceID, createPresentationCustom(aliceDID, func(claims map[string]interface{}, _ *vc.VerifiablePresentation) {
			delete(claims, "exp")
		}))
		assert.ErrorIs(t, err, errPresentationWithoutExpiration)
	})
	t.Run("presentation does not contain an ID", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)

		vpWithoutID := createPresentationCustom(aliceDID, func(claims map[string]interface{}, _ *vc.VerifiablePresentation) {
			delete(claims, "jti")
		}, vcAlice)
		err := m.Add(testServiceID, vpWithoutID)
		assert.ErrorIs(t, err, errPresentationWithoutID)
	})
	t.Run("not a JWT", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		err := m.Add(testServiceID, vc.VerifiablePresentation{})
		assert.ErrorIs(t, err, errUnsupportedPresentationFormat)
	})

	t.Run("registration", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			m, presentationVerifier := setupModule(t, storageEngine)
			presentationVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil)

			err := m.Add(testServiceID, vpAlice)
			require.NoError(t, err)

			_, tag, err := m.Get(testServiceID, nil)
			require.NoError(t, err)
			assert.Equal(t, "1", string(*tag)[tagPrefixLength:])
		})
		t.Run("valid longer than its credentials", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)

			vcAlice := createCredential(authorityDID, aliceDID, nil, func(claims map[string]interface{}) {
				claims["exp"] = time.Now().Add(time.Hour)
			})
			vpAlice := createPresentation(aliceDID, vcAlice)
			err := m.Add(testServiceID, vpAlice)
			assert.ErrorIs(t, err, errPresentationValidityExceedsCredentials)
		})
		t.Run("not conform to Presentation Definition", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)

			// Presentation Definition only allows did:example DIDs
			otherVP := createPresentation(unsupportedDID, createCredential(unsupportedDID, unsupportedDID, nil, nil))
			err := m.Add(testServiceID, otherVP)
			require.ErrorContains(t, err, "presentation does not fulfill Presentation ServiceDefinition")

			_, tag, _ := m.Get(testServiceID, nil)
			assert.Equal(t, "0", string(*tag)[tagPrefixLength:])
		})
	})
	t.Run("retraction", func(t *testing.T) {
		vpAliceRetract := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
			vp.Type = append(vp.Type, retractionPresentationType)
			claims["retract_jti"] = vpAlice.ID.String()
		})
		t.Run("ok", func(t *testing.T) {
			m, presentationVerifier := setupModule(t, storageEngine)
			presentationVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, nil).Times(2)

			err := m.Add(testServiceID, vpAlice)
			require.NoError(t, err)
			err = m.Add(testServiceID, vpAliceRetract)
			assert.NoError(t, err)
		})
		t.Run("non-existent presentation", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			err := m.Add(testServiceID, vpAliceRetract)
			assert.ErrorIs(t, err, errRetractionReferencesUnknownPresentation)
		})
		t.Run("must not contain credentials", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
			}, vcAlice)
			err := m.Add(testServiceID, vp)
			assert.ErrorIs(t, err, errRetractionContainsCredentials)
		})
		t.Run("missing 'retract_jti' claim", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(_ map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
			})
			err := m.Add(testServiceID, vp)
			assert.ErrorIs(t, err, errInvalidRetractionJTIClaim)
		})
		t.Run("'retract_jti' claim in not a string", func(t *testing.T) {
			m, _ := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
				claims["retract_jti"] = 10
			})
			err := m.Add(testServiceID, vp)
			assert.ErrorIs(t, err, errInvalidRetractionJTIClaim)
		})
	})
}

func Test_Module_Get(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Run("ok", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		require.NoError(t, m.store.add(testServiceID, vpAlice, nil))
		presentations, tag, err := m.Get(testServiceID, nil)
		assert.NoError(t, err)
		assert.Equal(t, []vc.VerifiablePresentation{vpAlice}, presentations)
		assert.Equal(t, "1", string(*tag)[tagPrefixLength:])
	})
	t.Run("ok - retrieve delta", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		require.NoError(t, m.store.add(testServiceID, vpAlice, nil))
		presentations, _, err := m.Get(testServiceID, nil)
		require.NoError(t, err)
		require.Len(t, presentations, 1)
	})
	t.Run("not a server for this service ID", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		_, _, err := m.Get("other", nil)
		assert.ErrorIs(t, err, ErrServerModeDisabled)
	})
}

func setupModule(t *testing.T, storageInstance storage.Engine) (*Module, *verifier.MockVerifier) {
	resetStore(t, storageInstance.GetSQLDatabase())
	ctrl := gomock.NewController(t)
	mockVerifier := verifier.NewMockVerifier(ctrl)
	mockVCR := vcr.NewMockVCR(ctrl)
	mockVCR.EXPECT().Verifier().Return(mockVerifier).AnyTimes()
	m := New(storageInstance, mockVCR)
	require.NoError(t, m.Configure(core.ServerConfig{}))
	m.services = testDefinitions()
	m.serverDefinitions = map[string]ServiceDefinition{
		testServiceID: m.services[testServiceID],
	}
	require.NoError(t, m.Start())
	return m, mockVerifier
}

func TestModule_Configure(t *testing.T) {
	serverConfig := core.ServerConfig{}
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
	t.Run("non-existent directory", func(t *testing.T) {
		config := Config{
			Definitions: ServiceDefinitionsConfig{
				Directory: "test/non_existent",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.ErrorContains(t, err, "unable to read definitions directory 'test/non_existent'")
	})
}

func TestModule_Search(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Run("ok", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		require.NoError(t, m.store.add(testServiceID, vpAlice, nil))
		results, err := m.Search(testServiceID, map[string]string{
			"credentialSubject.id": aliceDID.String(),
		})
		assert.NoError(t, err)
		assert.Equal(t, []SearchResult{
			{
				VP:     vpAlice,
				Fields: nil,
			},
		}, results)
	})
	t.Run("not a client for this service ID", func(t *testing.T) {
		m, _ := setupModule(t, storageEngine)
		_, err := m.Search("other", nil)
		assert.ErrorIs(t, err, ErrServerModeDisabled)
	})
}
