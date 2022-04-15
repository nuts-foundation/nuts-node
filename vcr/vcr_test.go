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
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/verifier"
	"go.etcd.io/bbolt"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/test/io"
	vcrTypes "github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/stretchr/testify/assert"
)

func TestVCR_Start(t *testing.T) {

	t.Run("error - creating db", func(t *testing.T) {
		instance := NewVCRInstance(nil, nil, nil, nil, jsonld.NewTestJSONLDManager(t)).(*vcr)

		_ = instance.Configure(core.ServerConfig{Datadir: "test"})
		err := instance.Start()
		assert.EqualError(t, err, "mkdir test/vcr: not a directory")
	})

	t.Run("ok", func(t *testing.T) {
		instance := NewTestVCRInstance(t)

		_, err := os.Stat(instance.credentialsDBPath())
		assert.NoError(t, err)
	})

	t.Run("loads default indices", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		instance := NewVCRInstance(
			nil,
			nil,
			nil,
			network.NewTestNetworkInstance(path.Join(testDirectory, "network")),
			jsonld.NewTestJSONLDManager(t),
		).(*vcr)
		if err := instance.Configure(core.ServerConfig{Datadir: testDirectory}); err != nil {
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
		defer db.Close()
		if err != nil {
			t.Fatal(err)
		}
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

func TestVCR_Shutdown(t *testing.T) {
	m := newMockContext(t)

	_ = m.vcr.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
	err := m.vcr.Start()
	if !assert.NoError(t, err) {
		return
	}
	err = m.vcr.Shutdown()
	assert.NoError(t, err)
}

func TestVCR_Resolve(t *testing.T) {

	testInstance := func(t2 *testing.T) mockContext {
		ctx := newMockContext(t2)

		// add document
		doc := []byte(jsonld.TestOrganizationCredential)
		err := ctx.vcr.credentialCollection().Add([]leia.Document{doc})
		if !assert.NoError(t2, err) {
			t2.Fatal(err)
		}

		return ctx
	}

	testVC := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testVC)

	now := time.Now()
	timeFunc = func() time.Time {
		return now
	}
	defer func() {
		timeFunc = time.Now
	}()

	t.Run("ok", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(ssi.MustParseURI("NutsOrganizationCredential"), testVC.Issuer)

		vc, err := ctx.vcr.Resolve(*testVC.ID, &now)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, testVC, *vc)
	})

	t.Run("error - not valid yet", func(t *testing.T) {
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(ssi.MustParseURI("NutsOrganizationCredential"), testVC.Issuer)

		_, err := ctx.vcr.Resolve(*testVC.ID, &time.Time{})
		assert.Equal(t, vcrTypes.ErrInvalidPeriod, err)
	})

	t.Run("error - no longer valid", func(t *testing.T) {
		nextYear, _ := time.Parse(time.RFC3339, "2030-01-02T12:00:00Z")
		ctx := testInstance(t)
		ctx.vcr.trustConfig.AddTrust(ssi.MustParseURI("NutsOrganizationCredential"), testVC.Issuer)

		_, err := ctx.vcr.Resolve(*testVC.ID, &nextYear)
		assert.Equal(t, vcrTypes.ErrInvalidPeriod, err)
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
		assert.Equal(t, moduleName, instance.Name())
	})

	t.Run("ok - config defaults", func(t *testing.T) {
		cfg := instance.Config().(*Config)

		assert.Equal(t, DefaultConfig().strictMode, cfg.strictMode)
	})
}

func TestVcr_Validate(t *testing.T) {
	// load VC
	subject := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("test/vc.json")

	if err := json.Unmarshal(vcJSON, &subject); err != nil {
		t.Fatal(err)
	}

	// oad pub key
	pke := storage.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	issuer := did.MustParseDIDURL(subject.Issuer.String())
	newMethod, err := did.NewVerificationMethod(issuer, ssi.JsonWebKey2020, issuer, pk)
	if !assert.NoError(t, err) {
		return
	}
	didDocument := did.Document{ID: issuer}
	didDocument.AddAssertionMethod(newMethod)

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

		ctx.docResolver.EXPECT().Resolve(issuer, gomock.Any()).Return(&didDocument, nil, nil)
		ctx.keyResolver.EXPECT().ResolveSigningKey(testKID, &now).Return(pk, nil)

		err = instance.Validate(subject, true, true, &now)

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

		err := instance.Validate(subject, true, false, nil)

		assert.NoError(t, err)
	})

	t.Run("err - vc without id", func(t *testing.T) {
		ctx := newMockContext(t)
		instance := ctx.vcr
		subject := vc.VerifiableCredential{}

		err := instance.Validate(subject, true, false, nil)
		assert.EqualError(t, err, "verifying a credential requires it to have a valid ID")
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

func TestVcr_Untrusted(t *testing.T) {
	instance := NewTestVCRInstance(t)
	testCredential := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(jsonld.TestOrganizationCredential), &testCredential)

	// reindex
	err := instance.initJSONLDIndices()
	if !assert.NoError(t, err) {
		return
	}

	// add document
	doc := []byte(jsonld.TestOrganizationCredential)
	doc2 := []byte(strings.ReplaceAll(jsonld.TestOrganizationCredential, "#123", "#321"))
	_ = instance.credentialCollection().Add([]leia.Document{doc})
	// for duplicate detection
	_ = instance.credentialCollection().Add([]leia.Document{doc2})

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
				trusted, err := fn(ssi.MustParseURI("NutsOrganizationCredential"))

				if !assert.NoError(t, err) {
					return
				}

				assert.Len(t, trusted, outcomes[i][0])
			})

			t.Run("ok - trusted", func(t *testing.T) {
				instance.Trust(ssi.MustParseURI("NutsOrganizationCredential"), testCredential.Issuer)
				defer func() {
					instance.Untrust(ssi.MustParseURI("NutsOrganizationCredential"), testCredential.Issuer)
				}()
				trusted, err := fn(ssi.MustParseURI("NutsOrganizationCredential"))

				if !assert.NoError(t, err) {
					return
				}

				assert.Len(t, trusted, outcomes[i][1])
			})
		})
	}
}

func TestWhitespaceOrExactTokenizer(t *testing.T) {
	input := "a b c"

	assert.Equal(t, []string{"a", "b", "c", "a b c"}, whitespaceOrExactTokenizer(input))
}

func TestResolveNutsCommServiceOwner(t *testing.T) {
}
