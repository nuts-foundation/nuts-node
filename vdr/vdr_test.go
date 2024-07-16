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
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/sirupsen/logrus"
	logTest "github.com/sirupsen/logrus/hooks/test"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/core/to"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

// testCtx contains the controller and mocks needed fot testing the Manipulator
type vdrTestCtx struct {
	ctrl                *gomock.Controller
	vdr                 Module
	mockStore           *didstore.MockStore
	mockNetwork         *network.MockTransactions
	mockKeyStore        *nutsCrypto.MockKeyStore
	mockAmbassador      *didnuts.MockAmbassador
	ctx                 context.Context
	mockDocumentManager *didsubject.MockDocumentManager
	mockDocumentOwner   *didsubject.MockDocumentOwner
}

func newVDRTestCtx(t *testing.T) vdrTestCtx {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockAmbassador := didnuts.NewMockAmbassador(ctrl)
	mockStore := didstore.NewMockStore(ctrl)
	mockNetwork := network.NewMockTransactions(ctrl)
	mockKeyStore := nutsCrypto.NewMockKeyStore(ctrl)
	mockDocumentManager := didsubject.NewMockDocumentManager(ctrl)
	mockDocumentOwner := didsubject.NewMockDocumentOwner(ctrl)
	resolverRouter := &resolver.DIDResolverRouter{}
	vdr := NewVDR(mockKeyStore, mockNetwork, mockStore, nil, nil)
	vdr.networkAmbassador = mockAmbassador
	vdr.nutsDocumentManager = mockDocumentManager
	vdr.documentOwner = mockDocumentOwner
	vdr.didResolver = resolverRouter
	vdr.db = testDB(t)
	resolverRouter.Register(didnuts.MethodName, &didnuts.Resolver{Store: mockStore})
	return vdrTestCtx{
		ctrl:                ctrl,
		vdr:                 *vdr,
		mockAmbassador:      mockAmbassador,
		mockStore:           mockStore,
		mockNetwork:         mockNetwork,
		mockKeyStore:        mockKeyStore,
		mockDocumentManager: mockDocumentManager,
		mockDocumentOwner:   mockDocumentOwner,
		ctx:                 audit.TestContext(),
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
			client := nutsCrypto.NewMemoryCryptoInstance()
			keyID := did.DIDURL{DID: TestDIDA}
			keyID.Fragment = "1"
			_, _ = client.New(audit.TestContext(), nutsCrypto.StringNamingFunc(keyID.String()))
			vdr := NewVDR(client, nil, didstore.NewTestStore(t), nil, storage.NewTestStorageEngine(t))
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
			keyVendor := nutsCrypto.NewTestKey("did:nuts:vendor#keyVendor-1")

			didDocVendor := &did.Document{ID: did.MustParseDID("did:nuts:vendor")}
			vendorVM, err := did.NewVerificationMethod(did.MustParseDIDURL(keyVendor.KID()), ssi.JsonWebKey2020, didDocVendor.ID, keyVendor.Public())
			require.NoError(t, err)
			didDocVendor.AddCapabilityInvocation(vendorVM)
			test.mockDocumentManager.EXPECT().Create(gomock.Any(), gomock.Any()).Return(didDocVendor, keyVendor, nil)
			test.mockNetwork.EXPECT().CreateTransaction(test.ctx, gomock.Any()).AnyTimes()
			didDocVendor, _, err = test.vdr.NutsDocumentManager().Create(test.ctx, didsubject.DefaultCreationOptions())
			require.NoError(t, err)

			// organization
			keyOrg := nutsCrypto.NewTestKey("did:nuts:org#keyOrg-1")
			didDocOrg := &did.Document{ID: did.MustParseDID("did:nuts:org")}
			didDocOrg.Controller = []did.DID{didDocVendor.ID}
			orgVM, err := did.NewVerificationMethod(did.MustParseDIDURL(keyOrg.KID()), ssi.JsonWebKey2020, didDocOrg.ID, keyOrg.Public())
			require.NoError(t, err)
			didDocOrg.AddCapabilityInvocation(orgVM)
			test.mockDocumentManager.EXPECT().Create(gomock.Any(), gomock.Any()).Return(didDocOrg, keyOrg, nil)
			didDocOrg, _, err = test.vdr.NutsDocumentManager().Create(test.ctx, didsubject.DefaultCreationOptions().
				With(didnuts.KeyFlag(didsubject.AssertionMethodUsage|didsubject.KeyAgreementUsage)),
			)
			require.NoError(t, err)

			client := nutsCrypto.NewMemoryCryptoInstance()
			_, _ = client.New(audit.TestContext(), nutsCrypto.StringNamingFunc(keyVendor.KID()))
			_, _ = client.New(audit.TestContext(), nutsCrypto.StringNamingFunc(keyOrg.KID()))
			vdr := NewVDR(client, nil, didstore.NewTestStore(t), nil, storage.NewTestStorageEngine(t))
			tmpResolver := vdr.didResolver
			_ = vdr.Configure(*core.NewServerConfig())
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
			err := instance.Configure(core.ServerConfig{URL: "https://nuts.nl"})
			require.NoError(t, err)

			doc, md, err := instance.Resolver().Resolve(did.MustParseDID("did:web:example.com"), nil)

			assert.NoError(t, err)
			assert.NotNil(t, doc)
			assert.NotNil(t, md)
		})
		t.Run("resolves local DID from database", func(t *testing.T) {
			instance := NewVDR(nutsCrypto.NewMemoryCryptoInstance(), nil, nil, nil, storageInstance)
			err := instance.Configure(core.ServerConfig{URL: "https://example.com"})
			require.NoError(t, err)
			db := storageInstance.GetSQLDatabase()
			sqlDIDDocumentManager := didsubject.NewDIDDocumentManager(db)
			sqlDID := didsubject.DID{
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

	t.Run("ignores self-controlled documents", func(t *testing.T) {
		t.Cleanup(func() { hook.Reset() })
		ctx := newVDRTestCtx(t)
		ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&did.Document{ID: TestDIDA}, nil, nil)

		err := ctx.vdr.Migrate()

		require.NoError(t, err)
		// empty logs means all ok.
		assert.Nil(t, hook.LastEntry())
	})
	t.Run("makes documents self-controlled", func(t *testing.T) {
		t.Cleanup(func() { hook.Reset() })
		ctx := newVDRTestCtx(t)
		keyStore := nutsCrypto.NewMemoryCryptoInstance()
		key, err := keyStore.New(ctx.ctx, didnuts.DIDKIDNamingFunc)
		methodID := did.MustParseDIDURL(key.KID())
		methodID.ID = TestDIDA.ID
		vm, _ := did.NewVerificationMethod(methodID, ssi.JsonWebKey2020, TestDIDA, key.Public())
		documentA := did.Document{Context: []interface{}{did.DIDContextV1URI()}, ID: TestDIDA, Controller: []did.DID{TestDIDB}}
		documentA.AddAssertionMethod(vm)
		require.NoError(t, err)
		ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&documentA, &resolver.DocumentMetadata{}, nil).AnyTimes()
		ctx.mockStore.EXPECT().Resolve(TestDIDB, gomock.Any()).Return(&documentB, &resolver.DocumentMetadata{}, nil).AnyTimes()
		ctx.mockKeyStore.EXPECT().Resolve(gomock.Any(), gomock.Any()).Return(key, nil)
		ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).Return(testTransaction{}, nil)

		err = ctx.vdr.Migrate()

		require.NoError(t, err)
		// empty logs means all ok.
		assert.Nil(t, hook.LastEntry())
	})
	t.Run("deactivated is ignored", func(t *testing.T) {
		t.Cleanup(func() { hook.Reset() })
		ctx := newVDRTestCtx(t)
		ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(nil, nil, resolver.ErrDeactivated)

		err := ctx.vdr.Migrate()

		require.NoError(t, err)
		// empty logs means all ok.
		assert.Nil(t, hook.LastEntry())
	})
	t.Run("no active controller is ignored", func(t *testing.T) {
		t.Cleanup(func() { hook.Reset() })
		ctx := newVDRTestCtx(t)
		ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&documentA, nil, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDB, gomock.Any()).Return(&did.Document{ID: TestDIDB}, nil, nil)

		err := ctx.vdr.Migrate()

		require.NoError(t, err)
		// empty logs means all ok.
		assert.Nil(t, hook.LastEntry())
	})
	t.Run("error is logged", func(t *testing.T) {
		t.Cleanup(func() { hook.Reset() })
		ctx := newVDRTestCtx(t)
		ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(nil, nil, assert.AnError)

		err := ctx.vdr.Migrate()

		require.NoError(t, err)
		assertLog(t, "Could not update owned DID document, continuing with next document")
		assertLog(t, "assert.AnError general error for testing")
	})
	t.Run("no verification method is logged", func(t *testing.T) {
		t.Cleanup(func() { hook.Reset() })
		ctx := newVDRTestCtx(t)
		ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&did.Document{Controller: []did.DID{TestDIDB}}, nil, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDB, gomock.Any()).Return(&documentB, &resolver.DocumentMetadata{}, nil)

		err := ctx.vdr.Migrate()

		require.NoError(t, err)
		assertLog(t, "No verification method found in owned DID document")
	})
	t.Run("update error is logged", func(t *testing.T) {
		t.Cleanup(func() { hook.Reset() })
		ctx := newVDRTestCtx(t)
		keyStore := nutsCrypto.NewMemoryCryptoInstance()
		key, err := keyStore.New(ctx.ctx, didnuts.DIDKIDNamingFunc)
		// TestMethodDIDA is invalid because of thumbprint
		vm, _ := did.NewVerificationMethod(TestMethodDIDA, ssi.JsonWebKey2020, TestDIDA, key.Public())
		documentA := did.Document{Context: []interface{}{did.DIDContextV1URI()}, ID: TestDIDA, Controller: []did.DID{TestDIDB}}
		documentA.AddAssertionMethod(vm)
		require.NoError(t, err)
		ctx.mockDocumentOwner.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{TestDIDA}, nil)
		ctx.mockStore.EXPECT().Resolve(TestDIDA, gomock.Any()).Return(&documentA, &resolver.DocumentMetadata{}, nil).AnyTimes()
		ctx.mockStore.EXPECT().Resolve(TestDIDB, gomock.Any()).Return(&documentB, &resolver.DocumentMetadata{}, nil).AnyTimes()

		err = ctx.vdr.Migrate()

		require.NoError(t, err)
		assertLog(t, "Could not update owned DID document, continuing with next document")
		assertLog(t, "update DID document: invalid verificationMethod: key thumbprint does not match ID")
	})
}

func TestModule_Create(t *testing.T) {
	testKeyStore := nutsCrypto.NewMemoryCryptoInstance()
	rootdid := did.MustParseDID("did:web:example.com")

	t.Run("assert build DID document", func(t *testing.T) {
		db := testDB(t)
		m := Module{db: db, methodManagers: map[string]didsubject.MethodManager{
			didweb.MethodName: didweb.NewManager(rootdid, "iam", testKeyStore, db),
		}}

		documents, _, err := m.Create(audit.TestContext(), didsubject.DefaultCreationOptions())

		require.NoError(t, err)
		require.Len(t, documents, 1)
		document := documents[0]
		assert.Len(t, document.VerificationMethod, 1)
		assert.Len(t, document.Authentication, 1)
		assert.Len(t, document.CapabilityInvocation, 1)
		assert.Len(t, document.AssertionMethod, 1)
		assert.Len(t, document.KeyAgreement, 0)
	})
	t.Run("without options", func(t *testing.T) {
		db := testDB(t)
		m := Module{db: db, methodManagers: map[string]didsubject.MethodManager{
			didweb.MethodName: didweb.NewManager(rootdid, "iam", testKeyStore, db),
			"test":            didweb.NewManager(rootdid, "iam_also", testKeyStore, db), // because we want to test multiple methods
		}}

		documents, _, err := m.Create(audit.TestContext(), didsubject.DefaultCreationOptions())
		require.NoError(t, err)
		require.Len(t, documents, 2)
		IDs := make([]string, 2)
		for i, document := range documents {
			IDs[i] = document.ID.String()
		}
		slices.Sort(IDs)
		assert.True(t, strings.HasPrefix(IDs[0], "did:web:example.com:iam:"))
		assert.True(t, strings.HasPrefix(IDs[1], "did:web:example.com:iam_also"))

		// test alsoKnownAs requirements
		document := documents[0]
		assert.Len(t, document.AlsoKnownAs, 1)
	})
	t.Run("with unknown option", func(t *testing.T) {
		db := testDB(t)
		m := Module{db: db, methodManagers: map[string]didsubject.MethodManager{
			didweb.MethodName: didweb.NewManager(rootdid, "iam", testKeyStore, db),
		}}

		_, _, err := m.Create(audit.TestContext(), didsubject.DefaultCreationOptions().With(""))

		require.EqualError(t, err, "unknown option: string")
	})
	t.Run("already exists", func(t *testing.T) {
		db := testDB(t)
		m := Module{db: db, methodManagers: map[string]didsubject.MethodManager{
			didweb.MethodName: didweb.NewManager(rootdid, "iam", testKeyStore, db),
		}}
		opts := didsubject.DefaultCreationOptions().With(didsubject.SubjectCreationOption{Subject: "subject"})
		_, _, err := m.Create(audit.TestContext(), opts)
		require.NoError(t, err)

		_, _, err = m.Create(audit.TestContext(), opts)

		require.ErrorIs(t, err, didsubject.ErrDIDAlreadyExists)
	})
}

func TestVDR_Services(t *testing.T) {
	testKeyStore := nutsCrypto.NewMemoryCryptoInstance()
	rootdid := did.MustParseDID("did:web:example.com")
	db := testDB(t)
	m := Module{db: db, methodManagers: map[string]didsubject.MethodManager{
		didweb.MethodName: didweb.NewManager(rootdid, "iam", testKeyStore, db),
	}}
	subject := "subject"
	opts := didsubject.DefaultCreationOptions().With(didsubject.SubjectCreationOption{Subject: subject})
	documents, _, err := m.Create(audit.TestContext(), opts)

	require.NoError(t, err)
	require.Len(t, documents, 1)
	document := documents[0]

	t.Run("create", func(t *testing.T) {
		service := did.Service{Type: "test", ServiceEndpoint: "https://example.com"}

		services, err := m.CreateService(audit.TestContext(), subject, service)

		require.NoError(t, err)
		require.Len(t, services, 1)
		serviceID := services[0].ID
		assert.True(t, strings.HasPrefix(serviceID.String(), document.ID.String()))
		assert.Equal(t, "4zQgDc15kLf9pXbAUSeus7ERTC8UBeqDrBSys1S89why", serviceID.Fragment)
		t.Run("update", func(t *testing.T) {
			services, err := m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 1)

			services, err = m.UpdateService(audit.TestContext(), subject, serviceID, service)

			require.NoError(t, err)
			require.Len(t, services, 1)
			assert.NotEqual(t, "", services[0].ID.String())
			services, err = m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 1)
		})
		t.Run("delete", func(t *testing.T) {
			services, err := m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 1)

			err = m.DeleteService(audit.TestContext(), subject, services[0].ID)

			require.NoError(t, err)
			services, err = m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 0)
		})
	})
}

func TestVDR_AddVerificationMethod(t *testing.T) {
	testKeyStore := nutsCrypto.NewMemoryCryptoInstance()
	rootdid := did.MustParseDID("did:web:example.com")
	db := testDB(t)
	m := Module{db: db, methodManagers: map[string]didsubject.MethodManager{
		didweb.MethodName: didweb.NewManager(rootdid, "iam", testKeyStore, db),
		"test":            didweb.NewManager(rootdid, "iam_also", testKeyStore, db), // because we want to test multiple methods
	}}
	subject := "subject"
	opts := didsubject.DefaultCreationOptions().With(didsubject.SubjectCreationOption{Subject: subject})
	documents, _, err := m.Create(audit.TestContext(), opts)

	require.NoError(t, err)
	require.Len(t, documents, 2)
	document := documents[0]

	t.Run("ok", func(t *testing.T) {
		vms, err := m.AddVerificationMethod(audit.TestContext(), subject, didsubject.AssertionKeyUsage())

		require.NoError(t, err)
		require.Len(t, vms, 2)
		t.Run("update keeps alsoKnownAs", func(t *testing.T) {
			sqlDocumentManager := didsubject.NewDIDDocumentManager(db)

			latest, err := sqlDocumentManager.Latest(did.MustParseDID(document.ID.String()), nil)
			require.NoError(t, err)
			didDocument, err := latest.ToDIDDocument()

			require.NoError(t, err)
			assert.Len(t, didDocument.AlsoKnownAs, 1)
		})
	})
}

func TestVDR_Deactivate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	ctx := audit.TestContext()
	rootdid := did.MustParseDID("did:web:example.com")
	testKeyStore := nutsCrypto.NewMemoryCryptoInstance()

	t.Run("not found", func(t *testing.T) {
		db := testDB(t)
		m := Module{db: db, methodManagers: map[string]didsubject.MethodManager{
			didweb.MethodName: didweb.NewManager(rootdid, "iam", testKeyStore, db),
		}}

		err := m.Deactivate(ctx, "subject")
		require.ErrorIs(t, err, resolver.ErrNotFound)
	})
	t.Run("ok", func(t *testing.T) {
		db := testDB(t)
		m := Module{db: db, didResolver: didsubject.Resolver{DB: db}, methodManagers: map[string]didsubject.MethodManager{
			didweb.MethodName: didweb.NewManager(rootdid, "iam", testKeyStore, db),
		}}
		documents, subject, err := m.Create(ctx, didsubject.DefaultCreationOptions())
		require.NoError(t, err)
		require.Len(t, documents, 1)
		document := documents[0]

		// Sanity check for assertion after deactivation, check that we can find the private key
		exists, err := testKeyStore.Exists(ctx, documents[0].VerificationMethod[0].ID.String())
		require.NoError(t, err)
		require.True(t, exists)

		err = m.Deactivate(ctx, subject)
		require.NoError(t, err)

		_, _, err = m.Resolve(document.ID, nil)

		assert.Equal(t, err, resolver.ErrDeactivated)
	})
}

func TestModule_rollback(t *testing.T) {
	didId := didsubject.DID{
		ID:      "did:example:123",
		Subject: "subject",
	}
	didDocument := didsubject.DIDDocument{
		ID:        "1",
		DidID:     "did:example:123",
		UpdatedAt: time.Now().Add(-time.Hour).Unix(),
	}
	didChangeLog := didsubject.DIDChangeLog{
		DIDDocumentVersionID: "1",
		Type:                 "created",
		TransactionID:        "2",
	}
	saveExamples := func(t *testing.T, db *gorm.DB) {
		require.NoError(t, db.Save(&didId).Error)
		require.NoError(t, db.Save(&didDocument).Error)
		require.NoError(t, db.Save(&didChangeLog).Error)
	}

	t.Run("uncommited results in rollback", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		ctx.vdr.methodManagers = map[string]didsubject.MethodManager{
			"example": testMethod{},
		}
		db := ctx.vdr.db
		saveExamples(t, db)

		ctx.vdr.rollback(ctx.ctx)

		// check removal of DIDChangeLog
		didChangeLog := make([]didsubject.DIDChangeLog, 0)
		require.NoError(t, db.Find(&didChangeLog).Error)
		assert.Len(t, didChangeLog, 0)

		// check removal of  DIDDocument
		didDocuments := make([]didsubject.DIDDocument, 0)
		require.NoError(t, db.Find(&didDocuments).Error)
		assert.Len(t, didDocuments, 0)
	})
	t.Run("IsCommitted returns error", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		ctx.vdr.methodManagers = map[string]didsubject.MethodManager{
			"example": testMethod{error: assert.AnError},
		}
		db := ctx.vdr.db
		saveExamples(t, db)

		ctx.vdr.rollback(ctx.ctx)

		// check existence of DIDChangeLog
		didChangeLog := make([]didsubject.DIDChangeLog, 0)
		require.NoError(t, db.Find(&didChangeLog).Error)
		assert.Len(t, didChangeLog, 1)

		// check existence of DIDDocument
		didDocuments := make([]didsubject.DIDDocument, 0)
		require.NoError(t, db.Find(&didDocuments).Error)
		assert.Len(t, didDocuments, 1)
	})
	t.Run("commited by method removes changelog", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		ctx.vdr.methodManagers = map[string]didsubject.MethodManager{
			"example": testMethod{committed: true},
		}
		db := ctx.vdr.db
		saveExamples(t, db)

		ctx.vdr.rollback(ctx.ctx)

		// check removal of DIDChangeLog
		didChangeLog := make([]didsubject.DIDChangeLog, 0)
		require.NoError(t, db.Find(&didChangeLog).Error)
		assert.Len(t, didChangeLog, 0)

		// check existence of DIDDocument
		didDocuments := make([]didsubject.DIDDocument, 0)
		require.NoError(t, db.Find(&didDocuments).Error)
		assert.Len(t, didDocuments, 1)
	})
	t.Run("rollback removes all from transaction", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		ctx.vdr.methodManagers = map[string]didsubject.MethodManager{
			"example": testMethod{},
		}
		db := ctx.vdr.db
		saveExamples(t, db)
		didId2 := didsubject.DID{
			ID:      "did:example:321",
			Subject: "subject",
		}
		didDocument2 := didsubject.DIDDocument{
			ID:        "2",
			DidID:     "did:example:321",
			UpdatedAt: time.Now().Add(-time.Hour).Unix(),
		}
		didChangeLog2 := didsubject.DIDChangeLog{
			DIDDocumentVersionID: "2",
			Type:                 "created",
			TransactionID:        "2",
		}
		require.NoError(t, db.Save(&didId2).Error)
		require.NoError(t, db.Save(&didDocument2).Error)
		require.NoError(t, db.Save(&didChangeLog2).Error)

		ctx.vdr.rollback(ctx.ctx)

		// check removal of DIDChangeLog
		didChangeLog := make([]didsubject.DIDChangeLog, 0)
		require.NoError(t, db.Find(&didChangeLog).Error)
		assert.Len(t, didChangeLog, 0)

		// check removal of  DIDDocument
		didDocuments := make([]didsubject.DIDDocument, 0)
		require.NoError(t, db.Find(&didDocuments).Error)
		assert.Len(t, didDocuments, 0)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

type testTransaction struct {
	clock        uint32
	signingKey   jwk.Key
	signingKeyID string
	signingTime  time.Time
	ref          hash.SHA256Hash
	payloadHash  hash.SHA256Hash
	payloadType  string
	prevs        []hash.SHA256Hash
	pal          [][]byte
	data         []byte
}

func (s testTransaction) SigningKey() jwk.Key {
	return s.signingKey
}

func (s testTransaction) SigningKeyID() string {
	return s.signingKeyID
}

func (s testTransaction) SigningTime() time.Time {
	return s.signingTime
}

func (s testTransaction) Ref() hash.SHA256Hash {
	return s.ref
}

func (s testTransaction) PAL() [][]byte {
	return s.pal
}

func (s testTransaction) PayloadHash() hash.SHA256Hash {
	return s.payloadHash
}

func (s testTransaction) PayloadType() string {
	return s.payloadType
}
func (s testTransaction) SigningAlgorithm() string {
	panic("implement me")
}

func (s testTransaction) Previous() []hash.SHA256Hash {
	return s.prevs
}

func (s testTransaction) Version() dag.Version {
	panic("implement me")
}

func (s testTransaction) MarshalJSON() ([]byte, error) {
	panic("implement me")
}

func (s testTransaction) Data() []byte {
	return s.data
}

func (s testTransaction) Clock() uint32 {
	return s.clock
}

type testMethod struct {
	committed bool
	error     error
}

func (t testMethod) NewDocument(ctx context.Context, keyFlags didsubject.DIDKeyFlags) (*didsubject.DIDDocument, error) {
	return &didsubject.DIDDocument{}, nil
}

func (t testMethod) NewVerificationMethod(ctx context.Context, controller did.DID, keyUsage didsubject.DIDKeyFlags) (*did.VerificationMethod, error) {
	return nil, nil
}

func (t testMethod) Commit(ctx context.Context, event didsubject.DIDChangeLog) error {
	return nil
}

func (t testMethod) IsCommitted(ctx context.Context, event didsubject.DIDChangeLog) (bool, error) {
	return t.committed, t.error
}
