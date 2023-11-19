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

package discoveryservice

import (
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const serviceID = "urn:nuts.nl:usecase:eOverdrachtDev2023"

func TestModule_Name(t *testing.T) {
	assert.Equal(t, "DiscoveryService", (&Module{}).Name())
}

func TestModule_Shutdown(t *testing.T) {
	assert.NoError(t, (&Module{}).Shutdown())
}

func Test_Module_Add(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Run("ok", func(t *testing.T) {
		m := setupModule(t, storageEngine)

		err := m.Add(testServiceID, vpAlice)
		assert.NoError(t, err)

		_, timestamp, err := m.Get(testServiceID, 0)
		require.NoError(t, err)
		assert.Equal(t, Timestamp(1), *timestamp)
	})
	t.Run("replace presentation of same credentialRecord subject", func(t *testing.T) {
		m := setupModule(t, storageEngine)

		vpAlice2 := createPresentation(aliceDID, vcAlice)
		assert.NoError(t, m.Add(testServiceID, vpAlice))
		assert.NoError(t, m.Add(testServiceID, vpBob))
		assert.NoError(t, m.Add(testServiceID, vpAlice2))

		presentations, timestamp, err := m.Get(testServiceID, 0)
		require.NoError(t, err)
		assert.Equal(t, []vc.VerifiablePresentation{vpBob, vpAlice2}, presentations)
		assert.Equal(t, Timestamp(3), *timestamp)
	})
	t.Run("already exists", func(t *testing.T) {
		m := setupModule(t, storageEngine)

		err := m.Add(testServiceID, vpAlice)
		assert.NoError(t, err)
		err = m.Add(testServiceID, vpAlice)
		assert.EqualError(t, err, "presentation already exists")
	})
	t.Run("valid for too long", func(t *testing.T) {
		m := setupModule(t, storageEngine)
		def := m.services[testServiceID]
		def.PresentationMaxValidity = 1
		m.services[testServiceID] = def

		err := m.Add(testServiceID, vpAlice)
		assert.EqualError(t, err, "presentation is valid for too long (max 1s)")
	})
	t.Run("valid longer than its credentials", func(t *testing.T) {
		m := setupModule(t, storageEngine)

		vcAlice := createCredential(authorityDID, aliceDID, nil, func(claims map[string]interface{}) {
			claims["exp"] = time.Now().Add(time.Hour)
		})
		vpAlice := createPresentation(aliceDID, vcAlice)
		err := m.Add(testServiceID, vpAlice)
		assert.EqualError(t, err, "presentation is valid longer than the credentialRecord(s) it contains")
	})
	t.Run("not valid long enough", func(t *testing.T) {
		m := setupModule(t, storageEngine)
		def := m.services[testServiceID]
		def.PresentationMaxValidity = int((24 * time.Hour).Seconds() * 365)
		m.services[testServiceID] = def

		err := m.Add(testServiceID, vpAlice)
		assert.EqualError(t, err, "presentation is not valid for long enough (min 2190h0m0s)")
	})
	t.Run("presentation does not contain an ID", func(t *testing.T) {
		m := setupModule(t, storageEngine)

		vpWithoutID := createPresentationCustom(aliceDID, func(claims map[string]interface{}, _ *vc.VerifiablePresentation) {
			delete(claims, "jti")
		}, vcAlice)
		err := m.Add(testServiceID, vpWithoutID)
		assert.EqualError(t, err, "presentation does not have an ID")
	})
	t.Run("not a JWT", func(t *testing.T) {
		m := setupModule(t, storageEngine)
		err := m.Add(testServiceID, vc.VerifiablePresentation{})
		assert.EqualError(t, err, "only JWT presentations are supported")
	})
	t.Run("service unknown", func(t *testing.T) {
		m := setupModule(t, storageEngine)
		err := m.Add("unknown", vpAlice)
		assert.ErrorIs(t, err, ErrServiceNotFound)
	})

	t.Run("retraction", func(t *testing.T) {
		vpAliceRetract := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
			vp.Type = append(vp.Type, retractionPresentationType)
			claims["retract_jti"] = vpAlice.ID.String()
		})
		t.Run("ok", func(t *testing.T) {
			m := setupModule(t, storageEngine)
			err := m.Add(testServiceID, vpAlice)
			require.NoError(t, err)
			err = m.Add(testServiceID, vpAliceRetract)
			assert.NoError(t, err)
		})
		t.Run("non-existent presentation", func(t *testing.T) {
			m := setupModule(t, storageEngine)
			err := m.Add(testServiceID, vpAliceRetract)
			assert.EqualError(t, err, "retraction presentation refers to a non-existing presentation")
		})
		t.Run("must not contain credentials", func(t *testing.T) {
			m := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
			}, vcAlice)
			err := m.Add(testServiceID, vp)
			assert.EqualError(t, err, "retraction presentation must not contain credentials")
		})
		t.Run("missing 'retract_jti' claim", func(t *testing.T) {
			m := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(_ map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
			})
			err := m.Add(testServiceID, vp)
			assert.EqualError(t, err, "retraction presentation does not contain 'retract_jti' claim")
		})
		t.Run("'retract_jti' claim in not a string", func(t *testing.T) {
			m := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
				claims["retract_jti"] = 10
			})
			err := m.Add(testServiceID, vp)
			assert.EqualError(t, err, "retraction presentation 'retract_jti' claim is not a string")
		})
		t.Run("'retract_jti' claim in not a valid DID", func(t *testing.T) {
			m := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
				claims["retract_jti"] = "not a DID"
			})
			err := m.Add(testServiceID, vp)
			assert.EqualError(t, err, "retraction presentation 'retract_jti' claim is not a valid DID URL: invalid DID")
		})
		t.Run("'retract_jti' claim does not reference a presentation of the signer", func(t *testing.T) {
			m := setupModule(t, storageEngine)
			vp := createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
				vp.Type = append(vp.Type, retractionPresentationType)
				claims["retract_jti"] = bobDID.String()
			})
			err := m.Add(testServiceID, vp)
			assert.EqualError(t, err, "retraction presentation 'retract_jti' claim does not match JWT issuer")
		})
	})
}

func Test_Module_Get(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Run("1 entry, empty timestamp", func(t *testing.T) {
		m := setupModule(t, storageEngine)
		require.NoError(t, m.Add(testServiceID, vpAlice))
		presentations, timestamp, err := m.Get(testServiceID, 0)
		assert.NoError(t, err)
		assert.Equal(t, []vc.VerifiablePresentation{vpAlice}, presentations)
		assert.Equal(t, Timestamp(1), *timestamp)
	})
	t.Run("service unknown", func(t *testing.T) {
		m := setupModule(t, storageEngine)
		_, _, err := m.Get("unknown", 0)
		assert.ErrorIs(t, err, ErrServiceNotFound)
	})
}

func setupModule(t *testing.T, storageInstance storage.Engine) *Module {
	resetStore(t, storageInstance.GetSQLDatabase())
	m := New(storageInstance)
	require.NoError(t, m.Configure(core.ServerConfig{}))
	m.services = testDefinitions()
	m.serverDefinitions = map[string]Definition{
		testServiceID: m.services[testServiceID],
	}
	require.NoError(t, m.Start())
	return m
}

func TestModule_Configure(t *testing.T) {
	serverConfig := core.ServerConfig{}
	t.Run("duplicate ID", func(t *testing.T) {
		config := Config{
			Definitions: DefinitionsConfig{
				Directory: "test/duplicate_id",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.EqualError(t, err, "duplicate definition ID 'urn:nuts.nl:usecase:eOverdrachtDev2023' in file 'test/duplicate_id/2.json'")
	})
	t.Run("invalid JSON", func(t *testing.T) {
		config := Config{
			Definitions: DefinitionsConfig{
				Directory: "test/invalid_json",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.ErrorContains(t, err, "unable to parse definition file 'test/invalid_json/1.json'")
	})
	t.Run("invalid definition", func(t *testing.T) {
		config := Config{
			Definitions: DefinitionsConfig{
				Directory: "test/invalid_definition",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.ErrorContains(t, err, "unable to parse definition file 'test/invalid_definition/1.json'")
	})
	t.Run("non-existent directory", func(t *testing.T) {
		config := Config{
			Definitions: DefinitionsConfig{
				Directory: "test/non_existent",
			},
		}
		err := (&Module{config: config}).Configure(serverConfig)
		assert.ErrorContains(t, err, "unable to read definitions directory 'test/non_existent'")
	})
}
