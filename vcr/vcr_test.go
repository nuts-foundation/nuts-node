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
	"errors"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
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

			if ! assert.Len(t, cTemplates, 1) {
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
		ctx.vdr.EXPECT().Resolve(didMatcher{*vdr.RandomDID}, nil).Return(validDIDDocument(), nil, nil)
		ctx.crypto.EXPECT().PrivateKeyExists(vdr.RandomDID.String()).Return(true)
		ctx.crypto.EXPECT().SignDetachedJWS(gomock.Any(), vdr.RandomDID.String()).Return("sig", nil)
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

		var proof = make([]JsonWebSignature2020Proof, 1)
		err = issued.UnmarshalProofValue(&proof)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "sig", proof[0].Jws)
	})

	t.Run("error - unknown DID", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		ctx.vdr.EXPECT().Resolve(didMatcher{*vdr.RandomDID}, nil).Return(nil, nil, errors.New("b00m!"))

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
		ctx.vdr.EXPECT().Resolve(didMatcher{*vdr.RandomDID}, nil).Return(validDIDDocument(), nil, nil)
		ctx.crypto.EXPECT().PrivateKeyExists(vdr.RandomDID.String()).Return(true)
		ctx.crypto.EXPECT().SignDetachedJWS(gomock.Any(), vdr.RandomDID.String()).Return("sig", nil)

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - missing private key", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		ctx.vdr.EXPECT().Resolve(didMatcher{*vdr.RandomDID}, nil).Return(validDIDDocument(), nil, nil)
		ctx.crypto.EXPECT().PrivateKeyExists(vdr.RandomDID.String()).Return(false)

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - signing failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		ctx.vdr.EXPECT().Resolve(didMatcher{*vdr.RandomDID}, nil).Return(validDIDDocument(), nil, nil)
		ctx.crypto.EXPECT().PrivateKeyExists(vdr.RandomDID.String()).Return(true)
		ctx.crypto.EXPECT().SignDetachedJWS(gomock.Any(), vdr.RandomDID.String()).Return("", errors.New("b00m!"))

		_, err := instance.Issue(*cred)

		assert.Error(t, err)
	})

	t.Run("error - tx failed", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		defer ctx.ctrl.Finish()

		cred := validNutsOrganizationCredential()
		ctx.vdr.EXPECT().Resolve(didMatcher{*vdr.RandomDID}, nil).Return(validDIDDocument(), nil, nil)
		ctx.crypto.EXPECT().PrivateKeyExists(vdr.RandomDID.String()).Return(true)
		ctx.crypto.EXPECT().SignDetachedJWS(gomock.Any(), vdr.RandomDID.String()).Return("sig", nil)
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

type didMatcher struct {
	expected did.DID
}

func (d didMatcher) Matches(x interface{}) bool {
	did, ok := x.(did.DID)
	if !ok {
		return ok
	}

	return d.expected.String() == did.String()
}

func (d didMatcher) String() string {
	return "DID Matcher"
}

func validDIDDocument() *did.Document {
	doc := did.Document{}
	vm := did.VerificationMethod{
		ID: *vdr.RandomDID,
	}
	doc.AddAssertionMethod(&vm)
	return &doc
}

func validNutsOrganizationCredential() *did.VerifiableCredential {
	u, _ := url.Parse("NutsOrganizationCredential")
	uri := did.URI{URL: *u}

	u2, _ := url.Parse(vdr.RandomDID.String())
	issuer := did.URI{URL: *u2}

	var credentialSubject = make(map[string]interface{})
	credentialSubject["id"] = vdr.AltRandomDID.String()
	credentialSubject["organization"] = map[string]interface{}{
		"name": "Because we care B.V.",
		"city": "EIbergen",
	}

	return &did.VerifiableCredential{
		Type:              []did.URI{uri},
		Issuer:            issuer,
		IssuanceDate:      time.Now(),
		CredentialSubject: []interface{}{credentialSubject},
	}
}