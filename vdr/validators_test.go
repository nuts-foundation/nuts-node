package vdr

import (
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
			uri, _ := ssi.ParseURI("did:foo:123#foobar")
			didDoc.Service[0].ID = *uri
			a.doc = didDoc
		}, errors.New("invalid service: ID must have document prefix")},
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
