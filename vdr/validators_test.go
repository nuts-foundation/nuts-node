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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_verificationMethodValidator(t *testing.T) {
	table := []validatorTest{
		{"ok - valid document", func() did.Document {
			didDoc, _, _ := newDidDoc()
			return didDoc
		}, nil},
		{"nok - verificationMethod ID has no fragment", func() did.Document {
			didDoc, _, _ := newDidDoc()
			didDoc.VerificationMethod[0].ID.Fragment = ""
			return didDoc
		}, errors.New("invalid verificationMethod: ID must have a fragment")},
		{"nok - verificationMethod ID has wrong prefix", func() did.Document {
			didDoc, _, _ := newDidDoc()
			didDoc.VerificationMethod[0].ID.ID = "foo:123"
			return didDoc
		}, errors.New("invalid verificationMethod: ID must have document prefix")},
		{"nok - verificationMethod with duplicate id", func() did.Document {
			didDoc, _, _ := newDidDoc()
			method := didDoc.VerificationMethod[0]
			didDoc.VerificationMethod = append(didDoc.VerificationMethod, method)
			return didDoc
		}, errors.New("invalid verificationMethod: ID must be unique")},
		{"nok - verificationMethod with invalid thumbprint", func() did.Document {
			didDoc, _, _ := newDidDoc()
			keyID := didDoc.VerificationMethod[0].ID
			keyID.Fragment = "foobar"
			pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			vm, _ := did.NewVerificationMethod(keyID, didDoc.VerificationMethod[0].Type, didDoc.VerificationMethod[0].Controller, pk.Public())
			didDoc.VerificationMethod = append(didDoc.VerificationMethod, vm)
			return didDoc
		}, errors.New("invalid verificationMethod: key thumbprint does not match ID")},
	}
	tableDrivenValidation(t, table, verificationMethodValidator{})
}

func Test_basicServiceValidator(t *testing.T) {
	table := []validatorTest{
		{"ok - valid document", func() did.Document {
			didDoc, _, _ := newDidDoc()
			return didDoc
		}, nil},
		{"ok - service endpoint is not validated", func() did.Document {
			// service endpoint is validated in managedServiceValidator
			didDoc, _, _ := newDidDoc()
			didDoc.Service[0].ServiceEndpoint = "did:foo:123/serviceEndpoint?type=NutsComm"
			return didDoc
		}, nil},
		{"nok - service with duplicate id", func() did.Document {
			didDoc, _, _ := newDidDoc()
			svc := didDoc.Service[0]
			didDoc.Service = append(didDoc.Service, svc)
			return didDoc
		}, errors.New("invalid service: ID must be unique")},
		{"nok - service ID has no fragment", func() did.Document {
			didDoc, _, _ := newDidDoc()
			didDoc.Service[0].ID.Fragment = ""
			return didDoc
		}, errors.New("invalid service: ID must have a fragment")},
		{"nok - service ID has wrong prefix", func() did.Document {
			didDoc, _, _ := newDidDoc()
			uri := ssi.MustParseURI("did:foo:123#foobar")
			didDoc.Service[0].ID = uri
			return didDoc
		}, errors.New("invalid service: ID must have document prefix")},
		{"nok - service with duplicate type", func() did.Document {
			didDoc, _, _ := newDidDoc()
			svc := didDoc.Service[0]
			svc.ID.Fragment = "foobar"
			didDoc.Service = append(didDoc.Service, svc)
			return didDoc
		}, errors.New("invalid service: service type is duplicate")},
	}
	tableDrivenValidation(t, table, basicServiceValidator{})
}

func Test_managedServiceValidator(t *testing.T) {
	serviceResolver := didservice.NewMockServiceResolver(gomock.NewController(t))
	service := did.Service{Type: "referenced_service", ServiceEndpoint: "https://nuts.nl"}
	serviceRef := ssi.MustParseURI("did:nuts:123/serviceEndpoint?type=referenced_service")
	//TODO: what if Type contains a space? ref should be URL encoded, but what about dereferencing?

	table := []validatorTest{
		{"ok - valid document", func() did.Document {
			didDoc, _, _ := newDidDoc()
			return didDoc
		}, nil},
		{"ok - doesn't panic", func() did.Document {
			didDoc, _, _ := newDidDoc()
			didDoc.Service = nil
			return didDoc
		}, nil},
		{"ok - resolves string", func() did.Document {
			didDoc, _, _ := newDidDoc()
			didDoc.Service[0].ServiceEndpoint = serviceRef.String()

			serviceResolver.EXPECT().ResolveEx(ssi.MustParseURI(didDoc.Service[0].ServiceEndpoint.(string)), 0, 5, gomock.Any()).Return(service, nil)

			return didDoc
		}, nil},
		{"ok - resolves map", func() did.Document {
			didDoc, _, _ := newDidDoc()
			didDoc.Service[0].ServiceEndpoint = map[string]string{
				"reference":      serviceRef.String(),
				"url":            "super invalid but isn't validated",
				"otherReference": serviceRef.String(),
			}

			serviceResolver.EXPECT().ResolveEx(serviceRef, 0, 5, gomock.Any()).Return(service, nil).Times(2) // 2 of 3 entries need to be resolved

			return didDoc
		}, nil},
		{"nok - resolve fails", func() did.Document {
			didDoc, _, _ := newDidDoc()
			didDoc.Service[0].ServiceEndpoint = serviceRef.String()

			serviceResolver.EXPECT().ResolveEx(serviceRef, 0, 5, gomock.Any()).Return(service, errors.New("resolve failed"))

			return didDoc
		}, errors.New("invalid service: resolve failed")},
		{"nok - invalid format", func() did.Document {
			didDoc, _, _ := newDidDoc()
			didDoc.Service[0].ServiceEndpoint = []string{serviceRef.String()}
			return didDoc
		}, errors.New("invalid service: invalid service format")},
	}
	tableDrivenValidation(t, table, managedServiceValidator{serviceResolver})

	t.Run("NutsComm", func(t *testing.T) {
		table = []validatorTest{
			{"ok", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "NutsComm"
				didDoc.Service[0].ServiceEndpoint = "grpc://nuts.nl:5555"
				return didDoc
			}, nil},
			{"nok - invalid scheme", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "NutsComm"
				return didDoc
			}, errors.New("invalid service: NutsComm: scheme must be grpc")},
			{"nok - validates after resolving", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "NutsComm"
				didDoc.Service[0].ServiceEndpoint = didDoc.ID.String() + "/serviceEndpoint?type=notNutsComm"

				service := did.Service{Type: "notNutsComm", ServiceEndpoint: "https://nuts.nl"}
				serviceResolver.EXPECT().ResolveEx(ssi.MustParseURI(didDoc.Service[0].ServiceEndpoint.(string)), 0, 5, gomock.Any()).Return(service, nil)
				return didDoc
			}, errors.New("invalid service: NutsComm: scheme must be grpc")},
			{"nok - invalid format", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "NutsComm"
				didDoc.Service[0].ServiceEndpoint = map[string]string{"NutsComm": "grpc://nuts.nl:5555"}
				return didDoc
			}, errors.New("invalid service: NutsComm: endpoint not a string")},
		}
		tableDrivenValidation(t, table, managedServiceValidator{serviceResolver})
	})

	t.Run("node-contact-info", func(t *testing.T) {
		table = []validatorTest{
			{"ok - node-contact-info all valid", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "node-contact-info"
				didDoc.Service[0].ServiceEndpoint = map[string]string{
					"name":      "name",
					"email":     "valid@email.address",
					"telephone": "is a string",
					"website":   "https://nuts.nl",
				}
				return didDoc
			}, nil},
			{"ok - minimal info", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "node-contact-info"
				didDoc.Service[0].ServiceEndpoint = map[string]string{
					"email": "valid@email.address",
				}
				return didDoc
			}, nil},
			{"ok - validates after resolving", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "node-contact-info"
				didDoc.Service[0].ServiceEndpoint = didDoc.ID.String() + "/serviceEndpoint?type=otherService"

				service := did.Service{Type: "otherService", ServiceEndpoint: map[string]any{"email": "valid@email.address"}}
				serviceResolver.EXPECT().ResolveEx(ssi.MustParseURI(didDoc.Service[0].ServiceEndpoint.(string)), 0, 5, gomock.Any()).Return(service, nil)
				return didDoc
			}, nil},
			{"nok - missing email", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "node-contact-info"
				didDoc.Service[0].ServiceEndpoint = map[string]string{}
				return didDoc
			}, errors.New("invalid service: node-contact-info: missing email")},
			{"nok - invalid email", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "node-contact-info"
				didDoc.Service[0].ServiceEndpoint = map[string]string{
					"email": "not a valid email",
				}
				return didDoc
			}, errors.New("invalid service: node-contact-info: invalid email")},
			{"nok - invalid website", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "node-contact-info"
				didDoc.Service[0].ServiceEndpoint = map[string]string{
					"email":   "valid@email.address",
					"website": "nuts.nl",
				}
				return didDoc
			}, errors.New("invalid service: node-contact-info: invalid website")},
			{"nok - contains unknown fields", func() did.Document {
				didDoc, _, _ := newDidDoc()
				didDoc.Service[0].Type = "node-contact-info"
				didDoc.Service[0].ServiceEndpoint = map[string]string{
					"email":      "valid@email.address",
					"whose this": "I don't know",
				}
				return didDoc
			}, errors.New("invalid service: node-contact-info: must only contain 'name', 'email', 'telephone', and 'website'")},
		}
		tableDrivenValidation(t, table, managedServiceValidator{serviceResolver})
	})
}

type validatorTest struct {
	name        string
	buildDoc    func() did.Document
	expectedErr error
}

func tableDrivenValidation(t *testing.T, tests []validatorTest, validator did.Validator) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.buildDoc())
			if tt.expectedErr == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expectedErr.Error())
			}
		})
	}
}
