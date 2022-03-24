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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"testing"
)

func Test_verificationMethodValidator(t *testing.T) {
	type args struct {
		doc did.Document
	}
	tests := []struct {
		name      string
		beforeFn  func(t *testing.T, a *args)
		wantedErr error
	}{
		{"ok - valid document", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			a.doc = didDoc
		}, nil},
		{"nok - verificationMethod ID has no fragment", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			didDoc.VerificationMethod[0].ID.Fragment = ""
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must have a fragment")},
		{"nok - verificationMethod ID has wrong prefix", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			didDoc.VerificationMethod[0].ID.ID = "foo:123"
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must have document prefix")},
		{"nok - verificationMethod with duplicate id", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			method := didDoc.VerificationMethod[0]
			didDoc.VerificationMethod = append(didDoc.VerificationMethod, method)
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: ID must be unique")},
		{"nok - verificationMethod with invalid thumbprint", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			keyID := didDoc.VerificationMethod[0].ID
			keyID.Fragment = "foobar"
			pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			vm, _ := did.NewVerificationMethod(keyID, didDoc.VerificationMethod[0].Type, didDoc.VerificationMethod[0].Controller, pk.Public())
			didDoc.VerificationMethod = append(didDoc.VerificationMethod, vm)
			a.doc = didDoc
		}, errors.New("invalid verificationMethod: key thumbprint does not match ID")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := args{}
			tt.beforeFn(t, &a)
			if err := (verificationMethodValidator{}).Validate(a.doc); err != nil || tt.wantedErr != nil {
				if err == nil {
					if tt.wantedErr != nil {
						t.Error("expected an error, got nothing")

					}
				} else {
					if tt.wantedErr == nil {

						t.Errorf("unexpected error: %v", err)
					} else {
						if tt.wantedErr.Error() != err.Error() {
							t.Errorf("wrong error\ngot:  %v\nwant: %v", err, tt.wantedErr)
						}
					}
				}
			}
		})
	}
}

func Test_serviceValidator(t *testing.T) {
	type args struct {
		doc did.Document
	}
	tests := []struct {
		name      string
		beforeFn  func(t *testing.T, a *args)
		wantedErr error
	}{
		{"ok - valid document", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			a.doc = didDoc
		}, nil},
		{"nok - service with duplicate id", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			svc := didDoc.Service[0]
			didDoc.Service = append(didDoc.Service, svc)
			a.doc = didDoc
		}, errors.New("invalid service: ID must be unique")},
		{"nok - service ID has no fragment", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			didDoc.Service[0].ID.Fragment = ""
			a.doc = didDoc
		}, errors.New("invalid service: ID must have a fragment")},
		{"nok - service ID has wrong prefix", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			uri := ssi.MustParseURI("did:foo:123#foobar")
			didDoc.Service[0].ID = uri
			a.doc = didDoc
		}, errors.New("invalid service: ID must have document prefix")},
		{"nok - service with duplicate type", func(t *testing.T, a *args) {
			didDoc, _, _ := newDidDoc()
			svc := didDoc.Service[0]
			svc.ID.Fragment = "foobar"
			didDoc.Service = append(didDoc.Service, svc)
			a.doc = didDoc
		}, errors.New("invalid service: service type is duplicate")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := args{}
			tt.beforeFn(t, &a)
			if err := (serviceValidator{}).Validate(a.doc); err != nil || tt.wantedErr != nil {
				if err == nil {
					if tt.wantedErr != nil {
						t.Error("expected an error, got nothing")

					}
				} else {
					if tt.wantedErr == nil {

						t.Errorf("unexpected error: %v", err)
					} else {
						if tt.wantedErr.Error() != err.Error() {
							t.Errorf("wrong error\ngot:  %v\nwant: %v", err, tt.wantedErr)
						}
					}
				}
			}
		})
	}
}
