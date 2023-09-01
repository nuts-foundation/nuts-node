/*
 * Nuts node
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

package vcr

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/go-leia/v4"
	"github.com/nuts-foundation/go-stoabs"
	bbolt2 "github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"go.etcd.io/bbolt"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/test/io"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestVCR_Configure(t *testing.T) {
	t.Run("error - creating issuer store", func(t *testing.T) {
		instance := NewVCRInstance(nil, nil, nil, jsonld.NewTestJSONLDManager(t), nil, storage.NewTestStorageEngine(t), pki.New()).(*vcr)

		err := instance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: "test"}))
		assert.EqualError(t, err, "failed to create leiaIssuerStore: mkdir test/vcr: not a directory")
	})
	t.Run("openid4vci", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		ctrl := gomock.NewController(t)
		vdrInstance := types.NewMockVDR(ctrl)
		vdrInstance.EXPECT().Resolver().AnyTimes()
		pkiProvider := pki.NewMockProvider(ctrl)
		pkiProvider.EXPECT().CreateTLSConfig(gomock.Any()).Return(nil, nil).AnyTimes()
		instance := NewVCRInstance(nil, vdrInstance, nil, jsonld.NewTestJSONLDManager(t), nil, storage.NewTestStorageEngine(t), pkiProvider).(*vcr)
		instance.config.OpenID4VCI.Enabled = true

		err := instance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory}))

		require.NoError(t, err)
	})
	t.Run("strictmode passed to client APIs", func(t *testing.T) {
		// load test VC
		testVC := vc.VerifiableCredential{}
		vcJSON, _ := os.ReadFile("test/vc.json")
		_ = json.Unmarshal(vcJSON, &testVC)
		issuerDID := did.MustParseDID(testVC.Issuer.String())
		testDirectory := io.TestDirectory(t)
		ctrl := gomock.NewController(t)
		pkiProvider := pki.NewMockProvider(ctrl)
		pkiProvider.EXPECT().CreateTLSConfig(gomock.Any()).Return(nil, nil).AnyTimes()
		localWalletResolver := openid4vci.NewMockIdentifierResolver(ctrl)
		localWalletResolver.EXPECT().Resolve(issuerDID).Return("https://example.com", nil).AnyTimes()
		vdrInstance := types.NewMockVDR(ctrl)
		vdrInstance.EXPECT().Resolver().AnyTimes()
		vdrInstance.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
		instance := NewVCRInstance(nil, vdrInstance, nil, jsonld.NewTestJSONLDManager(t), nil, storage.NewTestStorageEngine(t), pkiProvider).(*vcr)
		instance.config.OpenID4VCI.Enabled = true

		err := instance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory, Strictmode: true}))
		require.NoError(t, err)
		instance.localWalletResolver = localWalletResolver
		// test simulates an offer call which will not be executed since the target wallet does not have an HTTPS endpoint
		issuer, err := instance.GetOpenIDIssuer(context.Background(), issuerDID)
		require.NoError(t, err)
		err = issuer.OfferCredential(context.Background(), testVC, "http://example.com")

		assert.ErrorContains(t, err, "http request error: strictmode is enabled, but request is not over HTTPS")
	})
}

func TestVCR_Start(t *testing.T) {

	t.Run("ok", func(t *testing.T) {
		instance := NewTestVCRInstance(t)

		_, err := os.Stat(instance.credentialsDBPath())
		assert.NoError(t, err)
	})

	t.Run("loads default indices", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		ctrl := gomock.NewController(t)
		vdrInstance := types.NewMockVDR(ctrl)
		vdrInstance.EXPECT().Resolver().AnyTimes()
		instance := NewVCRInstance(
			nil,
			vdrInstance,
			network.NewTestNetworkInstance(t),
			jsonld.NewTestJSONLDManager(t),
			events.NewTestManager(t),
			storage.NewTestStorageEngine(t),
			pki.New(),
		).(*vcr)
		if err := instance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory})); err != nil {
			t.Fatal(err)
		}
		if err := instance.Start(); err != nil {
			t.Fatal(err)
		}
		// add a single document so indices are created
		if err := instance.credentialCollection().Add([]leia.Document{[]byte("{}")}); err != nil {
			t.Fatal(err)
		}
		if err := instance.Shutdown(); err != nil {
			t.Fatal(err)
		}

		dbPath := instance.credentialsDBPath()
		db, err := bbolt.Open(dbPath, os.ModePerm, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		db.View(func(tx *bbolt.Tx) error {
			mainBucket := tx.Bucket([]byte("credentials"))

			if !assert.NotNil(t, mainBucket) {
				return nil
			}
			assert.NotNil(t, mainBucket.Bucket([]byte("index_id")))
			assert.NotNil(t, mainBucket.Bucket([]byte("index_issuer")))
			assert.NotNil(t, mainBucket.Bucket([]byte("index_subject")))
			assert.NotNil(t, mainBucket.Bucket([]byte("index_organization")))

			return nil
		})
	})
}

func TestVCR_Diagnostics(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	ctrl := gomock.NewController(t)
	vdrInstance := types.NewMockVDR(ctrl)
	vdrInstance.EXPECT().Resolver().AnyTimes()
	vdrInstance.EXPECT().ListOwned(gomock.Any()).Return([]did.DID{did.MustParseDID("did:web:example.com")}, nil)
	instance := NewVCRInstance(
		nil,
		vdrInstance,
		network.NewTestNetworkInstance(t),
		jsonld.NewTestJSONLDManager(t),
		events.NewTestManager(t),
		storage.NewTestStorageEngine(t),
		pki.New(),
	).(*vcr)
	instance.config.OpenID4VCI.Enabled = false
	if err := instance.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory})); err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Shutdown()

	diagnostics := instance.Diagnostics()

	assert.Len(t, diagnostics, 4)
	assert.Equal(t, "issuer", diagnostics[0].Name())
	assert.NotEmpty(t, diagnostics[0].Result())
	assert.Equal(t, "verifier", diagnostics[1].Name())
	assert.NotEmpty(t, diagnostics[1].Result())
	assert.Equal(t, "credential_count", diagnostics[2].Name())
	assert.Equal(t, 0, diagnostics[2].Result())
	assert.Equal(t, "wallet_credential_count", diagnostics[3].Name())
	assert.NotEmpty(t, diagnostics[3].Result())
}

func TestVCR_Resolve(t *testing.T) {

	testInstance := func(t2 *testing.T) mockContext {
		ctx := newMockContext(t2)

		// add document
		doc := []byte(jsonld.TestOrganizationCredential)
		err := ctx.vcr.credentialCollection().Add([]leia.Document{doc})
		require.NoError(t2, err)

		return ctx
	}

	testVC := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testVC)

	now := time.Now()

	t.Run("ok", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(ssi.MustParseURI("NutsOrganizationCredential"), testVC.Issuer)

		vc, err := ctx.vcr.Resolve(*testVC.ID, &now)
		require.NoError(t, err)

		assert.Equal(t, testVC, *vc)
	})

	t.Run("error - not valid yet", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(ssi.MustParseURI("NutsOrganizationCredential"), testVC.Issuer)

		_, err := ctx.vcr.Resolve(*testVC.ID, &time.Time{})
		assert.Equal(t, vcrTypes.ErrCredentialNotValidAtTime, err)
	})

	t.Run("error - no longer valid", func(t *testing.T) {
		nextYear, _ := time.Parse(time.RFC3339, "2030-01-02T12:00:00Z")
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(ssi.MustParseURI("NutsOrganizationCredential"), testVC.Issuer)

		_, err := ctx.vcr.Resolve(*testVC.ID, &nextYear)
		assert.Equal(t, vcrTypes.ErrCredentialNotValidAtTime, err)
	})

	t.Run("ok - revoked", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(ssi.MustParseURI("NutsOrganizationCredential"), testVC.Issuer)
		mockVerifier := verifier.NewMockVerifier(ctx.ctrl)
		ctx.vcr.verifier = mockVerifier
		mockVerifier.EXPECT().Verify(testVC, false, false, gomock.Any()).Return(vcrTypes.ErrRevoked)

		vc, err := ctx.vcr.Resolve(*testVC.ID, nil)

		assert.Equal(t, vcrTypes.ErrRevoked, err)
		assert.Equal(t, testVC, *vc)
	})

	t.Run("ok - untrusted", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.RemoveTrust(testVC.Type[0], testVC.Issuer)

		vc, err := ctx.vcr.Resolve(*testVC.ID, nil)

		assert.Equal(t, err, vcrTypes.ErrUntrusted)
		assert.Equal(t, testVC, *vc)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := testInstance(t)
		_, err := ctx.vcr.Resolve(ssi.URI{}, nil)

		assert.Equal(t, vcrTypes.ErrNotFound, err)
	})
}

func TestVcr_Instance(t *testing.T) {
	instance := NewTestVCRInstance(t)

	t.Run("ok - name", func(t *testing.T) {
		assert.Equal(t, ModuleName, instance.Name())
	})
}

func Test_vcr_GetOIDCIssuer(t *testing.T) {
	id := did.MustParseDID("did:nuts:123456789abcdefghi")
	identifier := "https://example.com/" + id.String()
	ctx := context.Background()
	t.Run("found DID, owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vdrInstance := types.NewMockVDR(ctrl)
		vdrInstance.EXPECT().IsOwner(ctx, id).Return(true, nil)
		identifierResolver := openid4vci.NewMockIdentifierResolver(ctrl)
		identifierResolver.EXPECT().Resolve(id).Return(identifier, nil)
		instance := NewTestVCRInstance(t)
		instance.vdrInstance = vdrInstance
		instance.localWalletResolver = identifierResolver

		actual, err := instance.GetOpenIDIssuer(ctx, id)

		require.NoError(t, err)
		assert.NotNil(t, actual)
	})
	t.Run("found DID, not owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		vdrInstance := types.NewMockVDR(ctrl)
		vdrInstance.EXPECT().IsOwner(ctx, id).Return(false, nil)
		identifierResolver := openid4vci.NewMockIdentifierResolver(ctrl)
		identifierResolver.EXPECT().Resolve(id).Return(identifier, nil)
		instance := NewTestVCRInstance(t)
		instance.vdrInstance = vdrInstance
		instance.localWalletResolver = identifierResolver

		actual, err := instance.GetOpenIDIssuer(ctx, id)

		require.Error(t, err)
		assert.Nil(t, actual)
	})
	t.Run("resolver error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		identifierResolver := openid4vci.NewMockIdentifierResolver(ctrl)
		identifierResolver.EXPECT().Resolve(id).Return("", errors.New("failed"))
		instance := NewTestVCRInstance(t)
		instance.localWalletResolver = identifierResolver

		actual, err := instance.GetOpenIDIssuer(ctx, id)

		require.Error(t, err)
		assert.Nil(t, actual)
	})
}

func Test_vcr_GetOIDCWallet(t *testing.T) {
	id := did.MustParseDID("did:nuts:123456789abcdefghi")
	identifier := "https://example.com/" + id.String()
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	vdrInstance := types.NewMockVDR(ctrl)
	vdrInstance.EXPECT().IsOwner(ctx, id).Return(true, nil)
	identifierResolver := openid4vci.NewMockIdentifierResolver(ctrl)
	identifierResolver.EXPECT().Resolve(id).Return(identifier, nil)
	instance := NewTestVCRInstance(t)
	instance.vdrInstance = vdrInstance
	instance.localWalletResolver = identifierResolver

	actual, err := instance.GetOpenIDHolder(ctx, id)

	require.NoError(t, err)
	assert.NotNil(t, actual)
}
func TestVcr_Untrusted(t *testing.T) {
	instance := NewTestVCRInstance(t)
	ctrl := gomock.NewController(t)
	mockDidResolver := types.NewMockDIDResolver(ctrl)
	vdrInstance := types.NewMockVDR(ctrl)
	vdrInstance.EXPECT().Resolver().Return(mockDidResolver).AnyTimes()
	instance.vdrInstance = vdrInstance
	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testCredential)

	// reindex
	err := instance.initJSONLDIndices()
	require.NoError(t, err)

	// add document
	doc := []byte(jsonld.TestOrganizationCredential)
	doc2 := []byte(strings.ReplaceAll(jsonld.TestOrganizationCredential, "#123", "#321"))
	_ = instance.credentialCollection().Add([]leia.Document{doc})
	// for duplicate detection
	_ = instance.credentialCollection().Add([]leia.Document{doc2})

	t.Run("Trusted", func(t *testing.T) {
		confirmTrustedStatus(t, instance, testCredential.Issuer, instance.Trusted, 1)
		confirmUntrustedStatus(t, instance.Trusted, 0)
	})
	t.Run("Untrusted", func(t *testing.T) {
		confirmTrustedStatus(t, instance, testCredential.Issuer, instance.Untrusted, 0)
		confirmUntrustedStatus(t, func(issuer ssi.URI) ([]ssi.URI, error) {
			mockDidResolver.EXPECT().Resolve(did.MustParseDIDURL(testCredential.Issuer.String()), nil).Return(nil, nil, nil)
			return instance.Untrusted(issuer)
		}, 1)
	})
	t.Run("Untrusted - did deactivated", func(t *testing.T) {
		confirmUntrustedStatus(t, func(issuer ssi.URI) ([]ssi.URI, error) {
			mockDidResolver.EXPECT().Resolve(did.MustParseDIDURL(testCredential.Issuer.String()), nil).Return(nil, nil, did.DeactivatedErr)
			return instance.Untrusted(issuer)
		}, 0)
	})
	t.Run("Untrusted - no active controller", func(t *testing.T) {
		confirmUntrustedStatus(t, func(issuer ssi.URI) ([]ssi.URI, error) {
			mockDidResolver.EXPECT().Resolve(did.MustParseDIDURL(testCredential.Issuer.String()), nil).Return(nil, nil, types.ErrNoActiveController)
			return instance.Untrusted(issuer)
		}, 0)
	})
}

func TestVcr_Migrate(t *testing.T) {
	const authCred = `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://nuts.nl/credentials/v1",
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
        "id": "did:nuts:owned"
    },
    "id": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#d2aa8189-db59-4dad-a3e5-60ca54f8fcc0",
    "issuer": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H",
    "type": [
        "NutsAuthorizationCredential",
        "VerifiableCredential"
    ]
}`
	const ownedNutsOrgCred = `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://nuts.nl/credentials/v1",
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
        "id": "did:nuts:owned"
    },
    "id": "owned",
    "issuer": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H",
    "type": [
        "NutsOrganizationCredential",
        "VerifiableCredential"
    ]
}`
	const otherNutsOrgCred = `
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://nuts.nl/credentials/v1",
        "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
    ],
    "credentialSubject": {
        "id": "did:nuts:foo"
    },
    "id": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H#2",
    "issuer": "did:nuts:4tzMaWfpizVKeA8fscC3JTdWBc3asUWWMj5hUFHdWX3H",
    "type": [
        "NutsOrganizationCredential",
        "VerifiableCredential"
    ]
}`
	ctx := audit.TestContext()
	ctrl := gomock.NewController(t)
	instance := NewTestVCRInstance(t)
	mockVDR := types.NewMockVDR(ctrl)
	ownedDID := did.MustParseDID("did:nuts:owned")
	mockVDR.EXPECT().IsOwner(gomock.Any(), ownedDID).Return(true, nil)
	mockVDR.EXPECT().IsOwner(gomock.Any(), did.MustParseDID("did:nuts:foo")).Return(false, nil)
	instance.vdrInstance = mockVDR

	// 3 credentials: 1 owned NutsAuthorizationCredential that must be ignored, 1 non-owned credential and finally 1 credential that should end up in the wallet
	require.NoError(t, instance.credentialCollection().Add([]leia.Document{[]byte(authCred)}))
	require.NoError(t, instance.credentialCollection().Add([]leia.Document{[]byte(ownedNutsOrgCred)}))
	require.NoError(t, instance.credentialCollection().Add([]leia.Document{[]byte(otherNutsOrgCred)}))
	// Wallet should be empty beforehand
	list, err := instance.wallet.List(ctx, ownedDID)
	require.NoError(t, err)
	require.Empty(t, list)
	require.NoError(t, err)

	err = instance.Migrate()
	require.NoError(t, err)

	// Check if the owned credential is now in the wallet
	list, err = instance.wallet.List(ctx, ownedDID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "owned", list[0].ID.String())
}

func TestVcr_restoreFromShelf(t *testing.T) {
	testVC := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testVC)
	testDir := io.TestDirectory(t)
	backupStorePath := path.Join(testDir, "data", "vcr", "backup-credentials.db")
	backupStore, err := bbolt2.CreateBBoltStore(backupStorePath)
	require.NoError(t, err)
	bytes := []byte(jsonld.TestOrganizationCredential)
	ref := sha1.Sum(bytes)
	_ = backupStore.WriteShelf(context.Background(), credentialsBackupShelf, func(writer stoabs.Writer) error {
		return writer.Put(stoabs.BytesKey(ref[:]), bytes)
	})
	_ = backupStore.Close(context.Background())

	store := NewTestVCRInstanceInDir(t, testDir)
	_ = store.Trust(testVC.Type[0], testVC.Issuer)
	require.NoError(t, err)
	result, err := store.Resolve(*testVC.ID, nil)
	require.NoError(t, err)
	assert.Equal(t, testVC, *result)
}

func confirmUntrustedStatus(t *testing.T, fn func(issuer ssi.URI) ([]ssi.URI, error), numUntrusted int) {
	trusted, err := fn(ssi.MustParseURI("NutsOrganizationCredential"))

	require.NoError(t, err)

	assert.Len(t, trusted, numUntrusted)
}

func confirmTrustedStatus(t *testing.T, trustManager TrustManager, issuer ssi.URI, fn func(issuer ssi.URI) ([]ssi.URI, error), numTrusted int) {
	trustManager.Trust(ssi.MustParseURI("NutsOrganizationCredential"), issuer)
	defer func() {
		trustManager.Untrust(ssi.MustParseURI("NutsOrganizationCredential"), issuer)
	}()
	trusted, err := fn(ssi.MustParseURI("NutsOrganizationCredential"))

	require.NoError(t, err)

	assert.Len(t, trusted, numTrusted)
}

func TestWhitespaceOrExactTokenizer(t *testing.T) {
	input := "a b c"

	assert.Equal(t, []string{"a", "b", "c", "a b c"}, whitespaceOrExactTokenizer(input))
}
