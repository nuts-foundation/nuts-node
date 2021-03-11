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
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
)

func TestVCR_Configure(t *testing.T) {

	t.Run("error - creating db", func(t *testing.T) {
		instance := NewVCRInstance(nil, nil, nil).(*vcr)

		err := instance.Configure(core.ServerConfig{Datadir: "test"})
		assert.Error(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		instance := NewVCRInstance(nil, nil, nil).(*vcr)

		err := instance.Configure(core.ServerConfig{Datadir: testDir})
		if !assert.NoError(t, err) {
			return
		}

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
			_, err = os.Stat(fsPath)
			assert.NoError(t, err)
		})
	})
}

func TestVCR_Search(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestVCRInstance(testDir)

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
	q.AddClause(concept.Eq("company.name", "Because we care BV"))

	creds, err := instance.Search(q)
	if !assert.NoError(t, err) {
		return
	}

	assert.Len(t, creds, 1)

	cs := creds[0].CredentialSubject[0]
	m := cs.(map[string]interface{})
	c := m["company"].(map[string]interface{})

	assert.Equal(t, "Because we care BV", c["name"])
}

func TestVCR_Resolve(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestVCRInstance(testDir)
	testVC := did.VerifiableCredential{}
	_ = json.Unmarshal([]byte(concept.TestCredential), &testVC)

	// add document
	doc := leia.Document(concept.TestCredential)
	err := instance.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok", func(t *testing.T) {
		vc, err := instance.Resolve(testVC.ID.String())

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, testVC, vc)
	})

	t.Run("error - error from store", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		instance := NewTestVCRInstance(testDir)
		instance.store.Collection(leia.GlobalCollection).DropIndex("index_id")
		_, err := instance.Resolve(testVC.ID.String())

		assert.Error(t, err)
	})

	t.Run("error - not found", func(t *testing.T) {
		_, err := instance.Resolve("unknown")

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
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		ctx.vdr.EXPECT().ResolveAssertionKey(*vdr.RandomDID).Return(vdr.RandomDID.URI(), nil)
		ctx.crypto.EXPECT().SignJWS(gomock.Any(), gomock.Any(), vdr.RandomDID.String()).Return("hdr.pay.sig", nil)
		ctx.tx.EXPECT().CreateTransaction(
			"application/vc+json;type=NutsOrganizationCredential",
			gomock.Any(),
			vdr.RandomDID.String(),
			nil,
			gomock.Any(),
		).Return(nil, nil)

		issued, err := instance.Issue(*cred)

		assert.NoError(t, err)
		assert.NotNil(t, issued)

		var proof = make([]JSONWebSignature2020Proof, 1)
		err = issued.UnmarshalProofValue(&proof)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "hdr..sig", proof[0].Jws)
	})

	t.Run("error - unknown DID", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		ctx.vdr.EXPECT().ResolveAssertionKey(*vdr.RandomDID).Return(did.URI{}, errors.New("b00m!"))

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - issuer not a DID", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		cred.Issuer = did.URI{}

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - credential type unknown", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		cred.Type = []did.URI{}

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		cred.CredentialSubject = make([]interface{}, 0)
		ctx.vdr.EXPECT().ResolveAssertionKey(*vdr.RandomDID).Return(vdr.RandomDID.URI(), nil)
		ctx.crypto.EXPECT().SignJWS(gomock.Any(), gomock.Any(), vdr.RandomDID.String()).Return("hdr.pay.sig", nil)

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
		assert.True(t, errors.Is(err, credential.ErrValidation))
	})

	t.Run("error - signing failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		ctx.vdr.EXPECT().ResolveAssertionKey(*vdr.RandomDID).Return(vdr.RandomDID.URI(), nil)
		ctx.crypto.EXPECT().SignJWS(gomock.Any(), gomock.Any(), vdr.RandomDID.String()).Return("", errors.New("b00m!"))

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - tx failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		ctx.vdr.EXPECT().ResolveAssertionKey(*vdr.RandomDID).Return(vdr.RandomDID.URI(), nil)
		ctx.crypto.EXPECT().SignJWS(gomock.Any(), gomock.Any(), vdr.RandomDID.String()).Return("hdr.pay.sig", nil)
		ctx.tx.EXPECT().CreateTransaction(
			"application/vc+json;type=NutsOrganizationCredential",
			gomock.Any(),
			vdr.RandomDID.String(),
			nil,
			gomock.Any(),
		).Return(nil, errors.New("b00m!"))

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})
}

func TestVcr_Verify(t *testing.T) {
	// load VC
	vc := did.VerifiableCredential{}
	vcJSON, _ := ioutil.ReadFile("test/vc.json")
	json.Unmarshal(vcJSON, &vc)

	// oad pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := ioutil.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		at := time.Now()

		ctx.vdr.EXPECT().ResolveSigningKey(kid, &at).Return(pk, nil)

		err := instance.Verify(vc, at)

		assert.NoError(t, err)
	})

	t.Run("error - wrong hashed payload", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		vc2 := vc
		vc2.IssuanceDate = time.Now()

		ctx.vdr.EXPECT().ResolveSigningKey(kid, gomock.Any()).Return(pk, nil)

		err := instance.Verify(vc2, time.Now())

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "failed to verify signature")
	})

	t.Run("error - wrong hashed proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		at := time.Now()
		vc2 := vc
		pr := make([]JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Created = at
		vc2.Proof = []interface{}{pr[0]}

		ctx.vdr.EXPECT().ResolveSigningKey(kid, gomock.Any()).Return(pk, nil)

		err := instance.Verify(vc2, at)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "failed to verify signature")
	})

	t.Run("error - unknown credential", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		err := instance.Verify(did.VerifiableCredential{}, time.Now())

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "unknown credential type")
	})

	t.Run("error - invalid credential", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		uri, _ := did.ParseURI(credential.NutsOrganizationCredentialType)

		err := instance.Verify(did.VerifiableCredential{Type: []did.URI{*uri}}, time.Now())

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("error - no proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		vc2 := vc
		vc2.Proof = []interface{}{}

		err := instance.Verify(vc2, time.Now())

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "expected a single Proof for challenge generation")
	})

	t.Run("error - wrong jws in proof", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		at := time.Now()
		vc2 := vc
		pr := make([]JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Jws = ""
		vc2.Proof = []interface{}{pr[0]}

		err := instance.Verify(vc2, at)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "invalid 'jws' value in proof")
	})

	t.Run("error - wrong base64 encoding in jws", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		at := time.Now()
		vc2 := vc
		pr := make([]JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Jws = "abac..ab//"
		vc2.Proof = []interface{}{pr[0]}

		err := instance.Verify(vc2, at)

		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "illegal base64 data")
	})

	t.Run("error - resolving key", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		at := time.Now()

		ctx.vdr.EXPECT().ResolveSigningKey(kid, &at).Return(nil, errors.New("b00m!"))

		err := instance.Verify(vc, at)

		assert.Error(t, err)
	})

	t.Run("error - not valid yet", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()
		at := vc.IssuanceDate.Add(-1 * time.Minute)

		ctx.vdr.EXPECT().ResolveSigningKey(kid, gomock.Any()).Return(pk, nil)

		err := instance.Verify(vc, at)

		assert.Error(t, err)
	})
}

func validNutsOrganizationCredential() *did.VerifiableCredential {
	uri, _ := did.ParseURI(credential.NutsOrganizationCredentialType)
	issuer, _ := did.ParseURI(vdr.RandomDID.String())

	var credentialSubject = make(map[string]interface{})
	credentialSubject["id"] = vdr.AltRandomDID.String()
	credentialSubject["organization"] = map[string]interface{}{
		"name": "Because we care B.V.",
		"city": "EIbergen",
	}

	return &did.VerifiableCredential{
		Type:              []did.URI{*uri},
		Issuer:            *issuer,
		IssuanceDate:      time.Now(),
		CredentialSubject: []interface{}{credentialSubject},
	}
}
