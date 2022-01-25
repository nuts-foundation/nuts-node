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
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/network/dag"

	"github.com/nuts-foundation/nuts-node/network"
	"github.com/stretchr/testify/mock"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v2"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr"
)

func TestVCR_Configure(t *testing.T) {

	t.Run("loads default configs", func(t *testing.T) {
		instance := NewTestVCRInstance(t)

		concepts := instance.registry.Concepts()

		if !assert.Len(t, concepts, 2) {
			return
		}

		assert.Equal(t, "NutsAuthorizationCredential", concepts[0].CredentialType)
		assert.Equal(t, "authorization", concepts[0].Concept)
		assert.Equal(t, "NutsOrganizationCredential", concepts[1].CredentialType)
		assert.Equal(t, "organization", concepts[1].Concept)
	})
}

func TestVCR_Start(t *testing.T) {

	t.Run("error - creating db", func(t *testing.T) {
		instance := NewVCRInstance(nil, nil, nil, nil).(*vcr)

		_ = instance.Configure(core.ServerConfig{Datadir: "test"})
		err := instance.Start()
		assert.Error(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		instance := NewTestVCRInstance(t)

		_, err := os.Stat(instance.credentialsDBPath())
		assert.NoError(t, err)
	})
}

func TestVCR_SearchInternal(t *testing.T) {
	vc := concept.TestVC()
	issuer, _ := did.ParseDIDURL(vc.Issuer.String())
	testInstance := func(t2 *testing.T) (mockContext, concept.Query) {
		ctx := newMockContext(t2)

		// init template
		err := ctx.vcr.registry.Add(concept.ExampleConfig)
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}

		// reindex
		err = ctx.vcr.initIndices()
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}

		// add document
		doc := leia.DocumentFromString(concept.TestCredential)
		err = ctx.vcr.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}

		// query
		q, err := ctx.vcr.Registry().QueryFor(concept.ExampleConcept)
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}
		q.AddClause(concept.Prefix("human.eyeColour", "blue"))
		return ctx, q
	}

	reqCtx := context.Background()
	now := time.Now()
	timeFunc = func() time.Time {
		return now
	}
	defer func() {
		timeFunc = time.Now
	}()

	t.Run("ok", func(t *testing.T) {
		ctx, q := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.docResolver.EXPECT().Resolve(*issuer, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, nil)

		creds, err := ctx.vcr.search(reqCtx, q, false, &now)

		if !assert.NoError(t, err) {
			return
		}
		if !assert.Len(t, creds, 1) {
			return
		}

		cs := creds[0].CredentialSubject[0]
		m := cs.(map[string]interface{})
		c := m["human"].(map[string]interface{})
		assert.Equal(t, "fair", c["hairColour"])
	})

	t.Run("ok - untrusted", func(t *testing.T) {
		ctx, q := testInstance(t)

		creds, err := ctx.vcr.search(reqCtx, q, false, nil)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, creds, 0)
	})

	t.Run("ok - untrusted but allowed", func(t *testing.T) {
		ctx, q := testInstance(t)
		ctx.docResolver.EXPECT().Resolve(*issuer, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, nil)

		creds, err := ctx.vcr.search(reqCtx, q, true, nil)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, creds, 1)
	})

	t.Run("ok - revoked", func(t *testing.T) {
		ctx, q := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		rev := leia.DocumentFromString(concept.TestRevocation)
		ctx.vcr.store.Collection(revocationCollection).Add([]leia.Document{rev})
		creds, err := ctx.vcr.search(reqCtx, q, false, nil)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, creds, 0)
	})

	t.Run("err - DID resolution failed", func(t *testing.T) {
		ctx, q := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.docResolver.EXPECT().Resolve(*issuer, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, types.ErrNotFound)

		creds, err := ctx.vcr.search(reqCtx, q, false, nil)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, creds, 0)
	})

}

func TestVCR_Resolve(t *testing.T) {

	testInstance := func(t2 *testing.T) mockContext {
		ctx := newMockContext(t2)

		// add document
		doc := leia.DocumentFromString(concept.TestCredential)
		err := ctx.vcr.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}
		// register type in templates
		_ = ctx.vcr.registry.Add(concept.ExampleConfig)

		return ctx
	}

	testVC := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(concept.TestCredential), &testVC)
	issuer, _ := did.ParseDIDURL(testVC.Issuer.String())

	now := time.Now()
	timeFunc = func() time.Time {
		return now
	}
	defer func() {
		timeFunc = time.Now
	}()

	t.Run("ok", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(testVC.Type[0], testVC.Issuer)
		ctx.docResolver.EXPECT().Resolve(*issuer, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, nil)

		vc, err := ctx.vcr.Resolve(*testVC.ID, &now)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, testVC, *vc)
	})

	t.Run("error - not valid yet", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(testVC.Type[0], testVC.Issuer)

		_, err := ctx.vcr.Resolve(*testVC.ID, &time.Time{})
		assert.Equal(t, ErrInvalidPeriod, err)
	})

	t.Run("error - no longer valid", func(t *testing.T) {
		testVC := vc.VerifiableCredential{}
		_ = json.Unmarshal([]byte(concept.TestCredential), &testVC)
		nextYear, _ := time.Parse(time.RFC3339, "2030-01-02T12:00:00Z")
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(testVC.Type[0], testVC.Issuer)

		_, err := ctx.vcr.Resolve(*testVC.ID, &nextYear)
		assert.Equal(t, ErrInvalidPeriod, err)
	})

	t.Run("ok - revoked", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.RemoveTrust(testVC.Type[0], testVC.Issuer)
		rev := leia.DocumentFromString(concept.TestRevocation)
		ctx.vcr.store.Collection(revocationCollection).Add([]leia.Document{rev})

		vc, err := ctx.vcr.Resolve(*testVC.ID, nil)

		assert.Equal(t, err, ErrRevoked)
		assert.Equal(t, testVC, *vc)
	})

	t.Run("ok - untrusted", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.RemoveTrust(testVC.Type[0], testVC.Issuer)

		vc, err := ctx.vcr.Resolve(*testVC.ID, nil)

		assert.Equal(t, err, ErrUntrusted)
		assert.Equal(t, testVC, *vc)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := testInstance(t)
		_, err := ctx.vcr.Resolve(ssi.URI{}, nil)

		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("error - DID not found", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(testVC.Type[0], testVC.Issuer)
		ctx.docResolver.EXPECT().Resolve(*issuer, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, types.ErrNotFound)

		_, err := ctx.vcr.Resolve(*testVC.ID, &now)
		assert.ErrorIsf(t, err, types.ErrNotFound, fmt.Sprintf("unable to resolve DID Document (ID=%s): unable to find the DID document", testVC.Issuer.String()))
	})
}

func TestVcr_Instance(t *testing.T) {
	instance := NewTestVCRInstance(t)

	t.Run("ok - name", func(t *testing.T) {
		assert.Equal(t, moduleName, instance.Name())
	})

	t.Run("ok - config defaults", func(t *testing.T) {
		cfg := instance.Config().(*Config)

		assert.Equal(t, DefaultConfig().strictMode, cfg.strictMode)
	})
}

func TestVcr_Issue(t *testing.T) {
	documentMetadata := types.DocumentMetadata{
		SourceTransactions: []hash.SHA256Hash{hash.EmptyHash()},
	}
	document := did.Document{}
	document.AddAssertionMethod(&did.VerificationMethod{ID: *vdr.TestMethodDIDA})

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		now := time.Now()
		timeFunc = func() time.Time {
			return now
		}
		defer func() { timeFunc = time.Now }()

		cred := validNutsOrganizationCredential()
		cred.CredentialStatus = &vc.CredentialStatus{
			Type: "test",
		}
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, nil).Return(&document, &documentMetadata, nil)
		testKey := crypto.NewTestKey("kid")
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(testKey, nil)
		ctx.tx.EXPECT().CreateTransaction(
			mock.MatchedBy(func(tpl network.Template) bool {
				return tpl.Type == vcDocumentType && !tpl.AttachKey && tpl.Key == testKey
			}),
		)

		issued, err := instance.Issue(*cred)

		assert.NoError(t, err)
		assert.NotNil(t, issued)
		// Only type, subject, issuer and expiration date should be taken from input VC
		assert.Nil(t, issued.CredentialStatus, "not all fields should be copied from input VC")
		assert.Contains(t, issued.Type, cred.Type[0])
		assert.Equal(t, issued.CredentialSubject, cred.CredentialSubject)
		assert.Equal(t, issued.Issuer, cred.Issuer)
		assert.Equal(t, issued.ExpirationDate, cred.ExpirationDate)
		// issuer is trusted
		assert.True(t, instance.isTrusted(*issued))

		var proof = make([]vc.JSONWebSignature2020Proof, 1)
		err = issued.UnmarshalProofValue(&proof)
		if !assert.NoError(t, err) {
			return
		}

		assert.Contains(t, proof[0].Jws, "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..")
	})

	t.Run("ok - unknown type (also private, but with public override)", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		instance.config.OverrideIssueAllPublic = true
		cred := validNutsOrganizationCredential()
		uri, _ := ssi.ParseURI("unknownType")
		cred.Type = []ssi.URI{*uri}
		//expectedURIA, _ := ssi.ParseURI(fmt.Sprintf("%s/serviceEndpoint?type=NutsComm", vdr.TestDIDA.String()))
		//expectedURIB, _ := ssi.ParseURI(fmt.Sprintf("%s/serviceEndpoint?type=NutsComm", vdr.TestDIDB.String()))
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, gomock.Any()).Return(&document, &documentMetadata, nil)
		//serviceID, _ := ssi.ParseURI(fmt.Sprintf("%s#1", vdr.TestDIDA.String()))
		//service := did.Service{ID: *serviceID}
		//ctx.serviceResolver.EXPECT().Resolve(*expectedURIA, 5).Return(service, nil)
		//ctx.serviceResolver.EXPECT().Resolve(*expectedURIB, 5).Return(service, nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(crypto.NewTestKey("kid"), nil)

		var tpl network.Template
		ctx.tx.EXPECT().CreateTransaction(gomock.Any()).DoAndReturn(func(arg network.Template) (dag.Transaction, error) {
			tpl = arg
			return nil, nil
		})

		issued, err := instance.Issue(*cred)

		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, issued)
		assert.NotNil(t, ctx.vcr.registry.FindByType("unknownType"))
		assert.Empty(t, tpl.Participants)
	})

	t.Run("error - NutsComm service resolve error", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		cred := validNutsOrganizationCredential()
		uri, _ := ssi.ParseURI("unknownType")
		cred.Type = []ssi.URI{*uri}
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, gomock.Any()).Return(&document, &documentMetadata, nil)
		ctx.serviceResolver.EXPECT().Resolve(gomock.Any(), 5).Return(did.Service{}, errors.New("b00m!"))
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(crypto.NewTestKey("kid"), nil)

		_, err := instance.Issue(*cred)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "failed to resolve participating node (did=did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW): could not resolve NutsComm service owner: b00m!")
	})

	t.Run("error - unknown type in strict mode", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		instance.config = Config{strictMode: true}

		cred := validNutsOrganizationCredential()
		uri, _ := ssi.ParseURI("unknownType")
		cred.Type = []ssi.URI{*uri}

		_, err := instance.Issue(*cred)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "cannot issue non-predefined credential types in strict mode")
	})

	t.Run("error - too many types", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		cred := validNutsOrganizationCredential()
		cred.Type = append(cred.Type, cred.Type[0])

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - unknown DID", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		cred := validNutsOrganizationCredential()
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - issuer not a DID", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		cred := validNutsOrganizationCredential()
		cred.Issuer = ssi.URI{}

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - credential type unknown", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		cred := validNutsOrganizationCredential()
		cred.Type = []ssi.URI{}

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		cred := validNutsOrganizationCredential()
		cred.CredentialSubject = make([]interface{}, 0)
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, gomock.Any()).Return(&document, &documentMetadata, nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(crypto.NewTestKey("kid"), nil)

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
		assert.True(t, errors.Is(err, credential.ErrValidation))
	})

	t.Run("error - getting signer failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		cred := validNutsOrganizationCredential()
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, gomock.Any()).Return(&document, &documentMetadata, nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(nil, errors.New("b00m!"))

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - tx failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		key := crypto.NewTestKey("kid")

		cred := validNutsOrganizationCredential()
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, gomock.Any()).Return(&document, &documentMetadata, nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(key, nil)
		ctx.tx.EXPECT().CreateTransaction(gomock.Any()).Return(nil, errors.New("b00m!"))

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - trust failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		instance.trustConfig = trust.NewConfig("")

		cred := validNutsOrganizationCredential()
		cred.CredentialStatus = &vc.CredentialStatus{
			Type: "test",
		}
		ctx.docResolver.EXPECT().Resolve(*vdr.TestDIDA, gomock.Any()).Return(&document, &documentMetadata, nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(crypto.NewTestKey("kid"), nil)
		ctx.tx.EXPECT().CreateTransaction(gomock.Any()).Return(nil, nil)

		issued, err := instance.Issue(*cred)

		if !assert.Error(t, err) {
			return
		}

		assert.True(t, errors.Is(err, trust.ErrNoFilename))
		// TX still went through, so the credential is still returned
		assert.NotNil(t, issued)
	})
}

func TestVcr_Validate(t *testing.T) {
	// load VC
	subject := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")

	if err := json.Unmarshal(vcJSON, &subject); err != nil {
		t.Fatal(err)
	}

	issuer, _ := did.ParseDIDURL(subject.Issuer.String())

	// oad pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	now := time.Now()
	timeFunc = func() time.Time {
		return now
	}

	t.Cleanup(func() {
		timeFunc = time.Now
	})

	t.Run("ok - with signature verification", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		ctx.docResolver.EXPECT().Resolve(*issuer, &types.ResolveMetadata{ResolveTime: &now})
		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, &now).Return(pk, nil)

		err := instance.Validate(subject, true, true, &now)

		assert.NoError(t, err)
	})

	t.Run("ok - with clock one second off", func(t *testing.T) {
		almostNow := now.Add(-time.Second)

		subject.IssuanceDate = now
		subject.ExpirationDate = &now

		timeFunc = func() time.Time {
			return almostNow
		}

		t.Cleanup(func() {
			timeFunc = func() time.Time {
				return now
			}
		})

		ctx := newMockContext(t)
		instance := ctx.vcr

		ctx.docResolver.EXPECT().Resolve(*issuer, &types.ResolveMetadata{ResolveTime: &almostNow})

		err := instance.Validate(subject, true, false, nil)

		assert.NoError(t, err)
	})

	t.Run("err - with clock 10 seconds off", func(t *testing.T) {
		almostNow := now.Add(-10 * time.Second)

		subject.IssuanceDate = now
		subject.ExpirationDate = &now

		timeFunc = func() time.Time {
			return almostNow
		}

		t.Cleanup(func() {
			timeFunc = func() time.Time {
				return now
			}
		})

		ctx := newMockContext(t)
		instance := ctx.vcr

		err := instance.Validate(subject, true, false, nil)

		assert.Error(t, err)
	})
}

func TestVcr_Verify(t *testing.T) {
	// load VC
	subject := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &subject)
	issuer, _ := did.ParseDIDURL(subject.Issuer.String())

	// oad pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	now := time.Now()
	timeFunc = func() time.Time {
		return now
	}
	defer func() {
		timeFunc = time.Now
	}()

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, gomock.Any()).Return(pk, nil)
		ctx.docResolver.EXPECT().Resolve(*issuer, &types.ResolveMetadata{ResolveTime: &now}).Return(nil, nil, nil)

		err := instance.Verify(subject, nil)

		assert.NoError(t, err)
	})

	t.Run("error - invalid vm", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		vc2 := subject
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		u, _ := ssi.ParseURI(subject.Issuer.String() + "2")
		pr[0].VerificationMethod = *u
		vc2.Proof = []interface{}{pr[0]}

		err := instance.Verify(vc2, nil)

		assert.Error(t, err)
		assert.EqualError(t, err, "verification method is not of issuer")
	})

	t.Run("error - wrong hashed payload", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		vc2 := subject
		vc2.IssuanceDate = time.Now()

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(pk, nil)

		err := instance.Verify(vc2, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "failed to verify signature")
	})

	t.Run("error - wrong hashed proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		vc2 := subject
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Created = time.Now()
		vc2.Proof = []interface{}{pr[0]}

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(pk, nil)

		err := instance.Verify(vc2, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "failed to verify signature")
	})

	t.Run("error - unknown credential", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		err := instance.Verify(vc.VerifiableCredential{}, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "unknown credential type")
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		uri, _ := ssi.ParseURI(credential.NutsOrganizationCredentialType)

		err := instance.Verify(vc.VerifiableCredential{Type: []ssi.URI{*uri}}, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("error - no proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		vc2 := subject
		vc2.Proof = []interface{}{}

		err := instance.Verify(vc2, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "expected a single Proof for challenge generation")
	})

	t.Run("error - wrong jws in proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		vc2 := subject
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Jws = ""
		vc2.Proof = []interface{}{pr[0]}

		err := instance.Verify(vc2, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "invalid 'jws' value in proof")
	})

	t.Run("error - wrong base64 encoding in jws", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		vc2 := subject
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Jws = "abac..ab//"
		vc2.Proof = []interface{}{pr[0]}

		err := instance.Verify(vc2, nil)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "illegal base64 data")
	})

	t.Run("error - resolving key", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(nil, errors.New("b00m!"))

		err := instance.Verify(subject, nil)

		assert.Error(t, err)
	})

	t.Run("error - not valid yet", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		at := subject.IssuanceDate.Add(-1 * time.Minute)

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, gomock.Any()).Return(pk, nil)

		err := instance.Verify(subject, &at)

		assert.Error(t, err)
	})
}

func TestVcr_Revoke(t *testing.T) {
	// load VC
	vc := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &vc)

	// load example revocation
	r := credential.Revocation{}
	rJSON, _ := os.ReadFile("test/revocation.json")
	json.Unmarshal(rJSON, &r)

	// load pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	organizationCredentialConfig := concept.Config{}
	credentialBytes, _ := os.ReadFile("assets/NutsOrganizationCredential.config.yaml")
	_ = yaml.Unmarshal(credentialBytes, &organizationCredentialConfig)

	documentMetadata := types.DocumentMetadata{
		SourceTransactions: []hash.SHA256Hash{hash.EmptyHash()},
	}
	document := did.Document{}
	document.AddAssertionMethod(&did.VerificationMethod{ID: *vdr.TestMethodDIDA})

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		key := crypto.NewTestKey("kid")
		ctx.vcr.registry.Add(organizationCredentialConfig)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		ctx.vcr.writeCredential(vc)
		ctx.docResolver.EXPECT().Resolve(gomock.Any(), nil).Return(&document, &documentMetadata, nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(key, nil)
		ctx.tx.EXPECT().CreateTransaction(mock.MatchedBy(func(spec network.Template) bool {
			return spec.Type == revocationDocumentType && !spec.AttachKey
		}))
		r, err := ctx.vcr.Revoke(*vc.ID)

		if !assert.NoError(t, err) {
			return
		}

		assert.Contains(t, r.Proof.Jws, "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..")
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})

		_, err := ctx.vcr.Revoke(ssi.URI{})

		if !assert.Error(t, err) {
			return
		}

		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("error - already revoked", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		ctx.vcr.writeCredential(vc)

		err := ctx.vcr.writeRevocation(r)
		if !assert.NoError(t, err) {
			return
		}

		_, err = ctx.vcr.Revoke(*vc.ID)

		if !assert.Error(t, err) {
			return
		}

		assert.Equal(t, ErrRevoked, err)
	})

	t.Run("error - key resolve returns error", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		ctx.vcr.writeCredential(vc)
		ctx.docResolver.EXPECT().Resolve(gomock.Any(), nil).Return(&document, &documentMetadata, nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestMethodDIDA.String()).Return(nil, crypto.ErrKeyNotFound)

		_, err := ctx.vcr.Revoke(*vc.ID)

		if !assert.Error(t, err) {
			return
		}

		assert.True(t, errors.Is(err, crypto.ErrKeyNotFound))
	})
}

func TestVcr_Find(t *testing.T) {
	testInstance := func(t2 *testing.T) mockContext {
		ctx := newMockContext(t2)

		err := ctx.vcr.registry.Add(concept.ExampleConfig)
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}

		// reindex
		err = ctx.vcr.initIndices()
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}

		// add document
		doc := leia.DocumentFromString(concept.TestCredential)
		err = ctx.vcr.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}

		return ctx
	}

	vc := concept.TestVC()
	subject := "did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW"

	t.Run("ok", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.docResolver.EXPECT().Resolve(gomock.Any(), gomock.Any()).Return(nil, nil, nil)

		conc, err := ctx.vcr.Get(concept.ExampleConcept, false, subject)
		if !assert.NoError(t, err) {
			return
		}

		hairColour, err := conc.GetString("human.hairColour")
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "fair", hairColour)
	})

	t.Run("error - unknown concept", func(t *testing.T) {
		ctx := testInstance(t)
		_, err := ctx.vcr.Get("unknown", false, subject)

		assert.Error(t, err)
		assert.Equal(t, err, concept.ErrUnknownConcept)
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := testInstance(t)
		_, err := ctx.vcr.Get(concept.ExampleConcept, false, "unknown")

		assert.Error(t, err)
		assert.Equal(t, err, ErrNotFound)
	})
}

func TestVCR_Search(t *testing.T) {
	vc := concept.TestVC()
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.registry.Add(concept.ExampleConfig)
		err := ctx.vcr.initIndices()
		if !assert.NoError(t, err) {
			return
		}

		ctx.vcr.Trust(vc.Type[0], vc.Issuer)
		ctx.docResolver.EXPECT().Resolve(gomock.Any(), gomock.Any()).Return(nil, nil, nil)
		doc := leia.DocumentFromString(concept.TestCredential)
		ctx.vcr.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
		results, _ := ctx.vcr.Search(context.Background(), "human", false, map[string]string{"human.eyeColour": "blue/grey"})
		assert.Len(t, results, 1)
	})

	t.Run("error - unknown concept", func(t *testing.T) {
		ctx := newMockContext(t)

		results, err := ctx.vcr.Search(context.Background(), "unknown", false, map[string]string{"human.eyeColour": "blue/grey"})
		assert.ErrorIs(t, err, concept.ErrUnknownConcept)
		assert.Nil(t, results)
	})
}

func TestVcr_Untrusted(t *testing.T) {
	instance := NewTestVCRInstance(t)
	vc := concept.TestVC()

	err := instance.registry.Add(concept.ExampleConfig)
	if !assert.NoError(t, err) {
		return
	}

	// reindex
	err = instance.initIndices()
	if !assert.NoError(t, err) {
		return
	}

	// add document
	doc := leia.DocumentFromString(concept.TestCredential)
	doc2 := leia.DocumentFromString(strings.ReplaceAll(concept.TestCredential, "#123", "#321"))
	_ = instance.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
	// for duplicate detection
	_ = instance.store.Collection(concept.ExampleType).Add([]leia.Document{doc2})

	funcs := []func(ssi.URI) ([]ssi.URI, error){
		instance.Trusted,
		instance.Untrusted,
	}

	outcomes := [][]int{
		{0, 1},
		{1, 0},
	}

	for i, fn := range funcs {
		name := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
		t.Run(name, func(t *testing.T) {
			t.Run("ok - untrusted", func(t *testing.T) {
				trusted, err := fn(vc.Type[1])

				if !assert.NoError(t, err) {
					return
				}

				assert.Len(t, trusted, outcomes[i][0])
			})

			t.Run("ok - trusted", func(t *testing.T) {
				instance.Trust(vc.Type[1], vc.Issuer)
				defer func() {
					instance.Untrust(vc.Type[1], vc.Issuer)
				}()
				trusted, err := fn(vc.Type[1])

				if !assert.NoError(t, err) {
					return
				}

				assert.Len(t, trusted, outcomes[i][1])
			})

			t.Run("error - unknown type", func(t *testing.T) {
				unknown := ssi.URI{}
				_, err := fn(unknown)

				if !assert.Error(t, err) {
					return
				}

				assert.Equal(t, ErrInvalidCredential, err)
			})
		})
	}
}

func TestVcr_verifyRevocation(t *testing.T) {
	// load revocation
	r := credential.Revocation{}
	rJSON, _ := os.ReadFile("test/revocation.json")
	json.Unmarshal(rJSON, &r)

	// Load pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, gomock.Any()).Return(pk, nil)

		err := instance.verifyRevocation(r)

		assert.NoError(t, err)
	})

	t.Run("error - invalid issuer", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		issuer, _ := ssi.ParseURI(r.Issuer.String() + "2")
		r2 := r
		r2.Issuer = *issuer

		err := instance.verifyRevocation(r2)

		assert.Error(t, err)
		assert.EqualError(t, err, "issuer of revocation is not the same as issuer of credential")
	})

	t.Run("error - invalid vm", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		vm, _ := ssi.ParseURI(r.Issuer.String() + "2")
		r2 := r
		p := *r2.Proof
		p.VerificationMethod = *vm
		r2.Proof = &p

		err := instance.verifyRevocation(r2)

		assert.Error(t, err)
		assert.EqualError(t, err, "verification method is not of issuer")
	})

	t.Run("error - invalid revocation", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		r2 := r
		r2.Issuer = ssi.URI{}

		err := instance.verifyRevocation(r2)

		assert.Error(t, err)
	})

	t.Run("error - invalid signature", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		r2 := r
		r2.Reason = "sig fails"

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, gomock.Any()).Return(pk, nil)

		err := instance.verifyRevocation(r2)

		assert.Error(t, err)
	})

	t.Run("error - incorrect signature", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		r2 := r
		r2.Proof = &vc.JSONWebSignature2020Proof{}

		err := instance.verifyRevocation(r2)

		assert.Error(t, err)
	})

	t.Run("error - resolving key", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, gomock.Any()).Return(nil, errors.New("b00m!"))

		err := instance.verifyRevocation(r)

		assert.Error(t, err)
	})

	t.Run("error - incorrect base64 encoded sig", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		r2 := r
		r2.Proof.Jws = "====..===="

		err := instance.verifyRevocation(r2)

		assert.Error(t, err)
	})
}

func TestVcr_generateProof(t *testing.T) {
	t.Run("incorrect key", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		instance := NewTestVCRInstance(t)
		key := crypto.TestKey{}
		kid, _ := ssi.ParseURI(testKID)

		err := instance.generateProof(vc, *kid, key)

		if !assert.Error(t, err) {
			return
		}
	})
}

func TestVcr_generateRevocationProof(t *testing.T) {
	t.Run("incorrect key", func(t *testing.T) {
		// load revocation
		r := credential.Revocation{}
		rJSON, _ := os.ReadFile("test/revocation.json")
		json.Unmarshal(rJSON, &r)

		// default stuff
		instance := NewTestVCRInstance(t)
		key := crypto.TestKey{}
		kid, _ := ssi.ParseURI(testKID)

		err := instance.generateRevocationProof(&r, *kid, key)

		if !assert.Error(t, err) {
			return
		}
	})
}

func TestWhitespaceOrExactTokenizer(t *testing.T) {
	input := "a b c"

	assert.Equal(t, []string{"a", "b", "c", "a b c"}, whitespaceOrExactTokenizer(input))
}

func TestResolveNutsCommServiceOwner(t *testing.T) {
	serviceID, _ := ssi.ParseURI(fmt.Sprintf("%s#1", vdr.TestDIDA.String()))
	expectedURIA, _ := ssi.ParseURI(fmt.Sprintf("%s/serviceEndpoint?type=NutsComm", vdr.TestDIDA.String()))
	service := did.Service{ID: *serviceID}

	t.Run("ok - correct did from service ID", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.serviceResolver.EXPECT().Resolve(*expectedURIA, 5).Return(service, nil)

		serviceOwner, err := ctx.vcr.resolveNutsCommServiceOwner(*vdr.TestDIDA)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, vdr.TestDIDA, serviceOwner)
	})

	t.Run("error from resolver", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.serviceResolver.EXPECT().Resolve(*expectedURIA, 5).Return(did.Service{}, errors.New("b00m!"))

		_, err := ctx.vcr.resolveNutsCommServiceOwner(*vdr.TestDIDA)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "could not resolve NutsComm service owner: b00m!")
	})
}

func validNutsOrganizationCredential() *vc.VerifiableCredential {
	uri, _ := ssi.ParseURI(credential.NutsOrganizationCredentialType)
	issuer, _ := ssi.ParseURI(vdr.TestDIDA.String())

	var credentialSubject = make(map[string]interface{})
	credentialSubject["id"] = vdr.TestDIDB.String()
	credentialSubject["organization"] = map[string]interface{}{
		"name": "Because we care B.V.",
		"city": "EIbergen",
	}

	return &vc.VerifiableCredential{
		Type:              []ssi.URI{*uri},
		Issuer:            *issuer,
		IssuanceDate:      time.Now(),
		CredentialSubject: []interface{}{credentialSubject},
	}
}
