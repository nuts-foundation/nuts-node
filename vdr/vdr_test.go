/*
 * Copyright (C) 2021 Nuts community
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

package vdr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/sirupsen/logrus"
	logTest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"io"
	"net/http"
	"strings"
	"testing"
)

// testCtx contains the controller and mocks needed fot testing the Manipulator
type vdrTestCtx struct {
	ctrl                *gomock.Controller
	vdr                 *Module
	mockStore           *didstore.MockStore
	mockNetwork         *network.MockTransactions
	keyStore            nutsCrypto.KeyStore
	mockAmbassador      *didnuts.MockAmbassador
	ctx                 context.Context
	mockDocumentManager *didsubject.MockDocumentManager
	mockDocumentOwner   *didsubject.MockDocumentOwner
	storageEngine       storage.Engine
}

func newVDRTestCtx(t *testing.T) vdrTestCtx {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockAmbassador := didnuts.NewMockAmbassador(ctrl)
	mockStore := didstore.NewMockStore(ctrl)
	mockNetwork := network.NewMockTransactions(ctrl)
	storageEngine := storage.NewTestStorageEngine(t)
	db := storageEngine.GetSQLDatabase()
	keyStore := nutsCrypto.NewDatabaseCryptoInstance(db)
	mockDocumentManager := didsubject.NewMockDocumentManager(ctrl)
	mockDocumentOwner := didsubject.NewMockDocumentOwner(ctrl)
	resolverRouter := &resolver.DIDResolverRouter{}
	vdr := NewVDR(keyStore, mockNetwork, mockStore, nil, nil)
	vdr.networkAmbassador = mockAmbassador
	vdr.nutsDocumentManager = mockDocumentManager
	vdr.documentOwner = mockDocumentOwner
	vdr.didResolver = resolverRouter
	vdr.Manager = &didsubject.SqlManager{
		DB:             db,
		MethodManagers: make(map[string]didsubject.MethodManager),
	}
	vdr.config = DefaultConfig()
	resolverRouter.Register(didnuts.MethodName, &didnuts.Resolver{Store: mockStore})
	return vdrTestCtx{
		ctrl:                ctrl,
		vdr:                 vdr,
		mockAmbassador:      mockAmbassador,
		mockStore:           mockStore,
		mockNetwork:         mockNetwork,
		keyStore:            keyStore,
		mockDocumentManager: mockDocumentManager,
		mockDocumentOwner:   mockDocumentOwner,
		ctx:                 audit.TestContext(),
		storageEngine:       storageEngine,
	}
}

func TestNewVDR(t *testing.T) {
	vdr := NewVDR(nil, nil, nil, nil, nil)
	assert.IsType(t, &Module{}, vdr)
}

func TestVDR_Start(t *testing.T) {
	t.Run("migration", func(t *testing.T) {
		t.Run("migrate on 0 document count", func(t *testing.T) {
			ctx := newVDRTestCtx(t)
			ctx.mockAmbassador.EXPECT().Start()
			ctx.mockStore.EXPECT().DocumentCount().Return(uint(0), nil)
			ctx.mockNetwork.EXPECT().Reprocess(context.Background(), "application/did+json").Return(nil, nil)

			err := ctx.vdr.Start()

			require.NoError(t, err)
		})
		t.Run("don't migrate on > 0 document count", func(t *testing.T) {
			ctx := newVDRTestCtx(t)
			ctx.mockAmbassador.EXPECT().Start()
			ctx.mockStore.EXPECT().DocumentCount().Return(uint(1), nil)

			err := ctx.vdr.Start()

			require.NoError(t, err)
		})
		t.Run("error on migration error", func(t *testing.T) {
			ctx := newVDRTestCtx(t)
			ctx.mockAmbassador.EXPECT().Start()
			testError := errors.New("test")
			ctx.mockStore.EXPECT().DocumentCount().Return(uint(0), testError)

			err := ctx.vdr.Start()

			assert.Equal(t, testError, err)
		})
	})

}

func TestVDR_ConflictingDocuments(t *testing.T) {

	t.Run("diagnostics", func(t *testing.T) {
		t.Run("ok - no conflicts/no documents", func(t *testing.T) {
			vdr := NewVDR(nil, nil, nil, nil, nil)
			vdr.store = didstore.NewTestStore(t)
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:0 total_count:0]", results[0].String())
			assert.Equal(t, "0", results[1].String())
		})

		t.Run("ok - 1 conflict", func(t *testing.T) {
			vdr := NewVDR(nil, nil, nil, nil, nil)
			vdr.store = didstore.NewTestStore(t)
			didDocument := did.Document{ID: TestDIDA}
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:0 total_count:1]", results[0].String())
			assert.Equal(t, "1", results[1].String())
		})

		t.Run("ok - 1 owned conflict", func(t *testing.T) {
			storageEngine := storage.NewTestStorageEngine(t)
			db := storageEngine.GetSQLDatabase()
			client := nutsCrypto.NewDatabaseCryptoInstance(db)
			keyID := did.DIDURL{DID: TestDIDA}
			keyID.Fragment = "1"
			_, _, _ = client.New(audit.TestContext(), nutsCrypto.StringNamingFunc(keyID.String()))
			vdr := NewVDR(client, nil, didstore.NewTestStore(t), nil, storageEngine)
			vdr.Config().(*Config).DIDMethods = []string{"web", "nuts"}
			_ = vdr.Configure(core.TestServerConfig())
			didDocument := did.Document{ID: TestDIDA}

			didDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: keyID})
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:1 total_count:1]", results[0].String())
			assert.Equal(t, "1", results[1].String())
		})

		t.Run("ok - 1 owned conflict in controlled document", func(t *testing.T) {
			// vendor
			test := newVDRTestCtx(t)
			_, keyVendor, _ := test.keyStore.New(audit.TestContext(), nutsCrypto.StringNamingFunc("did:nuts:vendor#keyVendor-1"))

			didDocVendor := &did.Document{ID: did.MustParseDID("did:nuts:vendor")}
			vendorVM, err := did.NewVerificationMethod(did.MustParseDIDURL("did:nuts:vendor#keyVendor-1"), ssi.JsonWebKey2020, didDocVendor.ID, keyVendor)
			require.NoError(t, err)
			didDocVendor.AddCapabilityInvocation(vendorVM)

			// organization
			_, keyOrg, _ := test.keyStore.New(audit.TestContext(), nutsCrypto.StringNamingFunc("did:nuts:org#keyOrg-1"))
			didDocOrg := &did.Document{ID: did.MustParseDID("did:nuts:org")}
			didDocOrg.Controller = []did.DID{didDocVendor.ID}
			orgVM, err := did.NewVerificationMethod(did.MustParseDIDURL("did:nuts:org#keyOrg-1"), ssi.JsonWebKey2020, didDocOrg.ID, keyOrg)
			require.NoError(t, err)
			didDocOrg.AddCapabilityInvocation(orgVM)

			// change vdr to allow for Configure()
			vdr := NewVDR(test.keyStore, nil, didstore.NewTestStore(t), nil, test.storageEngine)
			tmpResolver := vdr.didResolver
			vdr.Config().(*Config).DIDMethods = []string{"web", "nuts"}
			_ = vdr.Configure(core.TestServerConfig())
			vdr.didResolver = tmpResolver

			_ = vdr.store.Add(*didDocVendor, didstore.TestTransaction(*didDocVendor))
			_ = vdr.store.Add(*didDocOrg, didstore.TestTransaction(*didDocOrg))
			_ = vdr.store.Add(*didDocOrg, didstore.TestTransaction(*didDocOrg))
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:1 total_count:1]", results[0].String())
			assert.Equal(t, "2", results[1].String())
		})
	})
	t.Run("list", func(t *testing.T) {
		t.Run("ok - no conflicts", func(t *testing.T) {
			vdr := NewVDR(nil, nil, nil, nil, nil)
			vdr.store = didstore.NewTestStore(t)
			docs, meta, err := vdr.ConflictedDocuments()

			require.NoError(t, err)
			assert.Len(t, docs, 0)
			assert.Len(t, meta, 0)
		})

		t.Run("ok - 1 conflict", func(t *testing.T) {
			vdr := NewVDR(nil, nil, nil, nil, nil)
			vdr.store = didstore.NewTestStore(t)
			didDocument := did.Document{ID: TestDIDA}
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			docs, meta, err := vdr.ConflictedDocuments()

			require.NoError(t, err)
			assert.Len(t, docs, 1)
			assert.Len(t, meta, 1)
		})
	})
}

func TestVDR_Configure(t *testing.T) {
	storageInstance := storage.NewTestStorageEngine(t)
	t.Run("it can resolve using did:web", func(t *testing.T) {
		t.Run("not in database", func(t *testing.T) {
			client.DefaultCachingTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					Header:     map[string][]string{"Content-Type": {"application/json"}},
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"id": "did:web:example.com"}`)),
				}, nil
			})

			instance := NewVDR(nil, nil, nil, nil, storageInstance)
			instance.Config().(*Config).DIDMethods = []string{"web", "nuts"}
			err := instance.Configure(core.ServerConfig{URL: "https://nuts.nl"})
			require.NoError(t, err)

			doc, md, err := instance.Resolver().Resolve(did.MustParseDID("did:web:example.com"), nil)

			assert.NoError(t, err)
			assert.NotNil(t, doc)
			assert.NotNil(t, md)
		})
		t.Run("resolves local DID from database", func(t *testing.T) {
			db := storageInstance.GetSQLDatabase()
			instance := NewVDR(nutsCrypto.NewDatabaseCryptoInstance(db), nil, nil, nil, storageInstance)
			instance.Config().(*Config).DIDMethods = []string{"web", "nuts"}
			err := instance.Configure(core.ServerConfig{URL: "https://example.com"})
			require.NoError(t, err)
			sqlDIDDocumentManager := didsubject.NewDIDDocumentManager(db)
			sqlDID := orm.DID{
				ID:      "did:web:example.com",
				Subject: "subject",
			}
			_, err = sqlDIDDocumentManager.CreateOrUpdate(sqlDID, nil, nil)
			require.NoError(t, err)

			doc, md, err := instance.Resolver().Resolve(did.MustParseDID("did:web:example.com"), &resolver.ResolveMetadata{AllowDeactivated: true})

			assert.NoError(t, err)
			assert.NotNil(t, doc)
			assert.NotNil(t, md)
		})
	})
	t.Run("it can resolve using did:jwk", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		expectedJWK, err := jwk.FromRaw(privateKey.Public())
		require.NoError(t, err)

		jwkBytes, _ := json.Marshal(expectedJWK)
		inputDIDString := "did:jwk:" + base64.URLEncoding.EncodeToString(jwkBytes)
		inputDID, err := did.ParseDID(inputDIDString)
		require.NoError(t, err)

		instance := NewVDR(nil, nil, nil, nil, storageInstance)
		instance.Config().(*Config).DIDMethods = []string{"web", "nuts"}
		err = instance.Configure(core.TestServerConfig())
		require.NoError(t, err)

		doc, md, err := instance.Resolver().Resolve(*inputDID, nil)

		assert.NoError(t, err)
		assert.NotNil(t, doc)
		assert.NotNil(t, md)
		// Basic assertion on the actual key
		require.Len(t, doc.VerificationMethod, 1)
		assert.Equal(t, "P-256", doc.VerificationMethod[0].PublicKeyJwk["crv"])
	})
	t.Run("it can resolve using did:key", func(t *testing.T) {
		instance := NewVDR(nil, nil, nil, nil, storageInstance)
		instance.Config().(*Config).DIDMethods = []string{"web", "nuts"}
		err := instance.Configure(core.TestServerConfig())
		require.NoError(t, err)

		doc, md, err := instance.Resolver().Resolve(did.MustParseDID("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), nil)

		assert.NoError(t, err)
		assert.NotNil(t, doc)
		assert.NotNil(t, md)
	})
}

func TestVDR_Migrate(t *testing.T) {
	logrus.StandardLogger().Level = logrus.WarnLevel
	hook := &logTest.Hook{}
	logrus.StandardLogger().AddHook(hook)
	documentA := did.Document{Context: []interface{}{did.DIDContextV1URI()}, ID: TestDIDA, Controller: []did.DID{TestDIDB}}
	documentA.AddAssertionMethod(&did.VerificationMethod{ID: TestMethodDIDA})
	documentB := did.Document{ID: TestDIDB}
	documentB.AddCapabilityInvocation(&did.VerificationMethod{ID: *TestMethodDIDB})
	assertLog := func(t *testing.T, expected string) {
		t.Helper()
		require.NotNil(t, hook.LastEntry())
		msg, err := hook.LastEntry().String()
		require.NoError(t, err)
		assert.Contains(t, msg, expected)
	}
	t.Run("ignores non did:nuts", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		testDIDWeb := did.MustParseDID("did:web:example.com")
		ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{testDIDWeb}, nil)
		err := ctx.vdr.Migrate()
		assert.NoError(t, err)
		assert.Len(t, ctx.vdr.migrations, 3) // confirm its running allMigrations() that currently is only did:nuts
	})
	t.Run("controller migration", func(t *testing.T) {
		controllerMigrationSetup := func(t *testing.T) vdrTestCtx {
			t.Cleanup(func() { hook.Reset() })
			ctx := newVDRTestCtx(t)
			ctx.vdr.migrations = []migration{{ctx.vdr.migrateRemoveControllerFromDIDNuts, "remove controller"}}
			return ctx
		}
		t.Run("ignores self-controlled documents", func(t *testing.T) {
			ctx := controllerMigrationSetup(t)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&did.Document{ID: TestDIDA}, nil, nil)

			err := ctx.vdr.Migrate()

			require.NoError(t, err)
			// empty logs means all ok.
			assert.Nil(t, hook.LastEntry())
		})
		t.Run("makes documents self-controlled", func(t *testing.T) {
			ctx := controllerMigrationSetup(t)
			keyStore := nutsCrypto.NewMemoryCryptoInstance(t)
			keyRef, publicKey, err := keyStore.New(ctx.ctx, didnuts.DIDKIDNamingFunc)
			require.NoError(t, err)
			methodID := did.MustParseDIDURL(keyRef.KID)
			methodID.ID = TestDIDA.ID
			vm, _ := did.NewVerificationMethod(methodID, ssi.JsonWebKey2020, TestDIDA, publicKey)
			documentA := did.Document{Context: []interface{}{did.DIDContextV1URI()}, ID: TestDIDA, Controller: []did.DID{TestDIDB}}
			documentA.AddAssertionMethod(vm)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&documentA, &resolver.DocumentMetadata{}, nil).AnyTimes()
			ctx.mockStore.EXPECT().Resolve(TestDIDB, gomock.Any()).Return(&documentB, &resolver.DocumentMetadata{}, nil).AnyTimes()
			ctx.mockDocumentManager.EXPECT().Update(gomock.Any(), TestDIDA, gomock.Any()).Return(nil)

			err = ctx.vdr.Migrate()

			require.NoError(t, err)
			// empty logs means all ok.
			assert.Nil(t, hook.LastEntry())
		})
		t.Run("deactivated is ignored", func(t *testing.T) {
			ctx := controllerMigrationSetup(t)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(nil, nil, resolver.ErrDeactivated)

			err := ctx.vdr.Migrate()

			require.NoError(t, err)
			// empty logs means all ok.
			assert.Nil(t, hook.LastEntry())
		})
		t.Run("no active controller is ignored", func(t *testing.T) {
			ctx := controllerMigrationSetup(t)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&documentA, nil, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDB, gomock.Any()).Return(&did.Document{ID: TestDIDB}, nil, nil)

			err := ctx.vdr.Migrate()

			require.NoError(t, err)
			// empty logs means all ok.
			assert.Nil(t, hook.LastEntry())
		})
		t.Run("error is logged", func(t *testing.T) {
			ctx := controllerMigrationSetup(t)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(nil, nil, assert.AnError)

			err := ctx.vdr.Migrate()

			require.NoError(t, err)
			assertLog(t, "Could not update owned DID document, continuing with next document")
			assertLog(t, "assert.AnError general error for testing")
		})
		t.Run("no verification method is logged", func(t *testing.T) {
			ctx := controllerMigrationSetup(t)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&did.Document{Controller: []did.DID{TestDIDB}}, nil, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDB, gomock.Any()).Return(&documentB, &resolver.DocumentMetadata{}, nil)

			err := ctx.vdr.Migrate()

			require.NoError(t, err)
			assertLog(t, "No verification method found in owned DID document")
		})
		t.Run("update error is logged", func(t *testing.T) {
			ctx := controllerMigrationSetup(t)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
			ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&documentA, &resolver.DocumentMetadata{}, nil).AnyTimes()
			ctx.mockStore.EXPECT().Resolve(TestDIDB, gomock.Any()).Return(&documentB, &resolver.DocumentMetadata{}, nil).AnyTimes()
			ctx.mockDocumentManager.EXPECT().Update(gomock.Any(), TestDIDA, gomock.Any()).Return(assert.AnError)

			err := ctx.vdr.Migrate()

			require.NoError(t, err)
			assertLog(t, "Could not update owned DID document, continuing with next document")
			assertLog(t, "assert.AnError general error for testing")
		})
	})

	t.Run("history migration", func(t *testing.T) {
		historyMigrationSetup := func(t *testing.T) vdrTestCtx {
			t.Cleanup(func() { hook.Reset() })
			ctx := newVDRTestCtx(t)
			ctx.vdr.migrations = []migration{{ctx.vdr.migrateHistoryOwnedDIDNuts, "history migration"}}
			return ctx
		}
		t.Run("logs error", func(t *testing.T) {
			ctx := historyMigrationSetup(t)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
			ctx.mockStore.EXPECT().HistorySinceVersion(TestDIDA, 0).Return(nil, assert.AnError).AnyTimes()

			err := ctx.vdr.Migrate()

			assert.NoError(t, err)
			assertLog(t, "assert.AnError general error for testing")
		})
	})

	t.Run("add did:web to subject", func(t *testing.T) {
		didwebMigrationSetup := func(t *testing.T) vdrTestCtx {
			t.Cleanup(func() { hook.Reset() })
			ctx := newVDRTestCtx(t)
			ctx.vdr.migrations = []migration{{ctx.vdr.migrateAddDIDWebToOwnedDIDNuts, "add did:web to subject"}}
			return ctx
		}
		t.Run("web not in supported methods", func(t *testing.T) {
			logrus.StandardLogger().Level = logrus.InfoLevel
			defer func() { logrus.StandardLogger().Level = logrus.WarnLevel }()
			ctx := didwebMigrationSetup(t)
			ctx.vdr.migrations = []migration{{ctx.vdr.migrateAddDIDWebToOwnedDIDNuts, "add did:web to subject"}}
			ctx.vdr.config.DIDMethods = []string{"nuts"}
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)

			err := ctx.vdr.Migrate()

			require.NoError(t, err)
			assertLog(t, "did:web not in supported did methods. Abort migration.")
		})
		t.Run("logs error", func(t *testing.T) {
			ctx := didwebMigrationSetup(t)
			ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)

			err := ctx.vdr.Migrate()

			assert.NoError(t, err)
			assertLog(t, "Failed to add a did:web DID for did:nuts:") // test sql store does not contain TestDIDA
		})
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}
