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
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"os"
	"path"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/trust"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr"
)

func TestVCR_Configure(t *testing.T) {

	t.Run("error - creating db", func(t *testing.T) {
		instance := NewVCRInstance(nil, nil, nil).(*vcr)

		err := instance.Configure(core.ServerConfig{Datadir: "test"})
		assert.Error(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		instance := NewTestVCRInstance(testDir)

		t.Run("loads default templates", func(t *testing.T) {
			cTemplates := instance.registry.ConceptTemplates()

			if !assert.Len(t, cTemplates, 1) {
				return
			}

			orgTemplate := cTemplates["organization"]

			assert.NotNil(t, orgTemplate)
		})

		t.Run("initializes DB", func(t *testing.T) {
			fsPath := path.Join(testDir, "vcr", "credentials.db")
			_, err := os.Stat(fsPath)
			assert.NoError(t, err)
		})
	})
}

func TestVCR_Search(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestVCRInstance(testDir)
	vc := concept.TestVC()

	ct, err := concept.ParseTemplate(concept.ExampleTemplate)
	if !assert.NoError(t, err) {
		return
	}
	// init template
	err = instance.registry.Add(ct)
	if !assert.NoError(t, err) {
		return
	}

	// reindex
	err = instance.initIndices()
	if !assert.NoError(t, err) {
		return
	}

	// add document
	doc := leia.Document(concept.TestCredential)
	err = instance.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
	if !assert.NoError(t, err) {
		return
	}

	// query
	q, err := instance.Registry().QueryFor(concept.ExampleConcept)
	if !assert.NoError(t, err) {
		return
	}
	q.AddClause(concept.Prefix("human.eyeColour", "blue"))

	t.Run("ok", func(t *testing.T) {
		instance.Trust(vc.Type[0], vc.Issuer)
		defer func() {
			instance.Untrust(vc.Type[0], vc.Issuer)
		}()
		creds, err := instance.Search(q)
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
		creds, err := instance.Search(q)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, creds, 0)
	})

	t.Run("ok - revoked", func(t *testing.T) {
		instance.Trust(vc.Type[0], vc.Issuer)
		rev := leia.Document(concept.TestRevocation)
		instance.store.Collection(revocationCollection).Add([]leia.Document{rev})
		defer func() {
			instance.Untrust(vc.Type[0], vc.Issuer)
			instance.store.Collection(revocationCollection).Delete(rev)
		}()
		creds, err := instance.Search(q)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, creds, 0)
	})
}

func TestVCR_Resolve(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestVCRInstance(testDir)
	testVC := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(concept.TestCredential), &testVC)

	// add document
	doc := leia.Document(concept.TestCredential)
	err := instance.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok", func(t *testing.T) {
		instance.trustConfig.AddTrust(testVC.Type[0], testVC.Issuer)
		vc, err := instance.Resolve(*testVC.ID)

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, testVC, *vc)
	})

	t.Run("ok - revoked", func(t *testing.T) {
		instance.trustConfig.RemoveTrust(testVC.Type[0], testVC.Issuer)
		rev := leia.Document(concept.TestRevocation)
		instance.store.Collection(revocationCollection).Add([]leia.Document{rev})
		defer func() {
			instance.Untrust(testVC.Type[0], testVC.Issuer)
			instance.store.Collection(revocationCollection).Delete(rev)
		}()
		vc, err := instance.Resolve(*testVC.ID)

		assert.Equal(t, err, ErrRevoked)
		assert.Equal(t, testVC, *vc)
	})

	t.Run("ok - untrusted", func(t *testing.T) {
		instance.trustConfig.RemoveTrust(testVC.Type[0], testVC.Issuer)

		vc, err := instance.Resolve(*testVC.ID)

		assert.Equal(t, err, ErrUntrusted)
		assert.Equal(t, testVC, *vc)
	})

	t.Run("error - error from store", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		instance := NewTestVCRInstance(testDir)
		instance.store.Collection(leia.GlobalCollection).DropIndex("index_id")
		_, err := instance.Resolve(*testVC.ID)

		assert.Error(t, err)
	})

	t.Run("error - not found", func(t *testing.T) {
		_, err := instance.Resolve(ssi.URI{})

		assert.Equal(t, ErrNotFound, err)
	})
}

func TestVcr_Instance(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestVCRInstance(testDir)

	t.Run("ok - name", func(t *testing.T) {
		assert.Equal(t, moduleName, instance.Name())
	})

	t.Run("ok - configKey", func(t *testing.T) {
		assert.Equal(t, configKey, instance.ConfigKey())
	})

	t.Run("ok - config defaults", func(t *testing.T) {
		cfg := instance.Config().(*Config)

		assert.Equal(t, DefaultConfig(), *cfg)
	})
}

func TestVcr_Issue(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		cred := validNutsOrganizationCredential()
		cred.CredentialStatus = &vc.CredentialStatus{
			Type: "test",
		}
		ctx.keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(vdr.TestDIDA.URI(), nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestDIDA.String()).Return(crypto.NewTestKey("kid"), nil)
		ctx.tx.EXPECT().CreateTransaction(
			vcDocumentType,
			gomock.Any(),
			gomock.Any(),
			false,
			gomock.Any(),
			gomock.Any(),
		).Return(nil, nil)

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
		ctx.keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(ssi.URI{}, errors.New("b00m!"))

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
		ctx.keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(vdr.TestDIDA.URI(), nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestDIDA.String()).Return(crypto.NewTestKey("kid"), nil)

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
		assert.True(t, errors.Is(err, credential.ErrValidation))
	})

	t.Run("error - getting signer failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		cred := validNutsOrganizationCredential()
		ctx.keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(vdr.TestDIDA.URI(), nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestDIDA.String()).Return(nil, errors.New("b00m!"))

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - tx failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		key := crypto.NewTestKey("kid")

		cred := validNutsOrganizationCredential()
		ctx.keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(vdr.TestDIDA.URI(), nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestDIDA.String()).Return(key, nil)
		ctx.tx.EXPECT().CreateTransaction(
			vcDocumentType,
			gomock.Any(),
			key,
			false,
			gomock.Any(),
			gomock.Any(),
		).Return(nil, errors.New("b00m!"))

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
		ctx.keyResolver.EXPECT().ResolveAssertionKeyID(*vdr.TestDIDA).Return(vdr.TestDIDA.URI(), nil)
		ctx.crypto.EXPECT().Resolve(vdr.TestDIDA.String()).Return(crypto.NewTestKey("kid"), nil)
		ctx.tx.EXPECT().CreateTransaction(
			vcDocumentType,
			gomock.Any(),
			gomock.Any(),
			false,
			gomock.Any(),
			gomock.Any(),
		).Return(nil, nil)

		issued, err := instance.Issue(*cred)

		if !assert.Error(t, err) {
			return
		}

		assert.True(t, errors.Is(err, trust.ErrNoFilename))
		// TX still went through, so the credential is still returned
		assert.NotNil(t, issued)
	})
}

func TestVcr_Verify(t *testing.T) {
	// load VC
	subject := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &subject)

	// oad pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr

		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, nil).Return(pk, nil)

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

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		key := crypto.NewTestKey("kid")

		ctx.tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Times(2)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		ctx.vcr.writeCredential(vc)
		ctx.keyResolver.EXPECT().ResolveAssertionKeyID(gomock.Any()).Return(vc.Issuer, nil)
		ctx.crypto.EXPECT().Resolve(vc.Issuer.String()).Return(key, nil)
		ctx.tx.EXPECT().CreateTransaction(
			revocationDocumentType,
			gomock.Any(),
			key,
			false,
			gomock.Any(),
			gomock.Any(),
		)

		r, err := ctx.vcr.Revoke(*vc.ID)

		if !assert.NoError(t, err) {
			return
		}

		assert.Contains(t, r.Proof.Jws, "eyJhbGciOiJFUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..")
	})

	t.Run("error - not found", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Times(2)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})

		_, err := ctx.vcr.Revoke(ssi.URI{})

		if !assert.Error(t, err) {
			return
		}

		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("error - already revoked", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Times(2)
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

		ctx.tx.EXPECT().Subscribe(gomock.Any(), gomock.Any()).Times(2)
		ctx.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		ctx.vcr.writeCredential(vc)
		ctx.keyResolver.EXPECT().ResolveAssertionKeyID(gomock.Any()).Return(vc.Issuer, nil)
		ctx.crypto.EXPECT().Resolve(vc.Issuer.String()).Return(nil, crypto.ErrKeyNotFound)

		_, err := ctx.vcr.Revoke(*vc.ID)

		if !assert.Error(t, err) {
			return
		}

		assert.True(t, errors.Is(err, crypto.ErrKeyNotFound))
	})
}

func TestVcr_Find(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestVCRInstance(testDir)
	vc := concept.TestVC()
	subject := "did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW"

	ct, err := concept.ParseTemplate(concept.ExampleTemplate)
	if !assert.NoError(t, err) {
		return
	}
	// init template
	err = instance.registry.Add(ct)
	if !assert.NoError(t, err) {
		return
	}

	// reindex
	err = instance.initIndices()
	if !assert.NoError(t, err) {
		return
	}

	// add document
	doc := leia.Document(concept.TestCredential)
	err = instance.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
	if !assert.NoError(t, err) {
		return
	}

	// query
	q, err := instance.Registry().QueryFor(concept.ExampleConcept)
	if !assert.NoError(t, err) {
		return
	}
	q.AddClause(concept.Eq("human.eyeColour", "blue/grey"))

	t.Run("ok", func(t *testing.T) {
		instance.Trust(vc.Type[0], vc.Issuer)
		defer func() {
			instance.Untrust(vc.Type[0], vc.Issuer)
		}()
		conc, err := instance.Get(concept.ExampleConcept, subject)
		if !assert.NoError(t, err) {
			return
		}

		hairColour := conc.GetValue("human.hairColour")

		assert.Equal(t, "fair", hairColour)
	})

	t.Run("error - unknown concept", func(t *testing.T) {
		_, err := instance.Get("unknown", subject)

		assert.Error(t, err)
		assert.Equal(t, err, concept.ErrUnknownConcept)
	})

	t.Run("error - not found", func(t *testing.T) {
		_, err := instance.Get(concept.ExampleConcept, "unknown")

		assert.Error(t, err)
		assert.Equal(t, err, ErrNotFound)
	})
}

func TestVcr_Untrusted(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestVCRInstance(testDir)
	vc := concept.TestVC()

	ct, err := concept.ParseTemplate(concept.ExampleTemplate)
	if !assert.NoError(t, err) {
		return
	}
	// init template
	err = instance.registry.Add(ct)
	if !assert.NoError(t, err) {
		return
	}

	// reindex
	err = instance.initIndices()
	if !assert.NoError(t, err) {
		return
	}

	// add document
	doc := leia.Document(concept.TestCredential)
	err = instance.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
	if !assert.NoError(t, err) {
		return
	}

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
		testDir := io.TestDirectory(t)
		instance := NewTestVCRInstance(testDir)
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
		testDir := io.TestDirectory(t)
		instance := NewTestVCRInstance(testDir)
		key := crypto.TestKey{}
		kid, _ := ssi.ParseURI(testKID)

		err := instance.generateRevocationProof(&r, *kid, key)

		if !assert.Error(t, err) {
			return
		}
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
