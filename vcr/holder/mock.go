// Code generated by MockGen. DO NOT EDIT.
// Source: vcr/holder/interface.go
//
// Generated by this command:
//
//	mockgen -destination=vcr/holder/mock.go -package=holder -source=vcr/holder/interface.go
//

// Package holder is a generated GoMock package.
package holder

import (
	context "context"
	reflect "reflect"

	ssi "github.com/nuts-foundation/go-did"
	did "github.com/nuts-foundation/go-did/did"
	vc "github.com/nuts-foundation/go-did/vc"
	core "github.com/nuts-foundation/nuts-node/core"
	gomock "go.uber.org/mock/gomock"
)

// MockWallet is a mock of Wallet interface.
type MockWallet struct {
	ctrl     *gomock.Controller
	recorder *MockWalletMockRecorder
}

// MockWalletMockRecorder is the mock recorder for MockWallet.
type MockWalletMockRecorder struct {
	mock *MockWallet
}

// NewMockWallet creates a new mock instance.
func NewMockWallet(ctrl *gomock.Controller) *MockWallet {
	mock := &MockWallet{ctrl: ctrl}
	mock.recorder = &MockWalletMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWallet) EXPECT() *MockWalletMockRecorder {
	return m.recorder
}

// BuildPresentation mocks base method.
func (m *MockWallet) BuildPresentation(ctx context.Context, credentials []vc.VerifiableCredential, options PresentationOptions, signerDID *did.DID, validateVC bool) (*vc.VerifiablePresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuildPresentation", ctx, credentials, options, signerDID, validateVC)
	ret0, _ := ret[0].(*vc.VerifiablePresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BuildPresentation indicates an expected call of BuildPresentation.
func (mr *MockWalletMockRecorder) BuildPresentation(ctx, credentials, options, signerDID, validateVC any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuildPresentation", reflect.TypeOf((*MockWallet)(nil).BuildPresentation), ctx, credentials, options, signerDID, validateVC)
}

// Delete mocks base method.
func (m *MockWallet) Delete(ctx context.Context, subjectDID did.DID, id ssi.URI) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", ctx, subjectDID, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockWalletMockRecorder) Delete(ctx, subjectDID, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockWallet)(nil).Delete), ctx, subjectDID, id)
}

// Diagnostics mocks base method.
func (m *MockWallet) Diagnostics() []core.DiagnosticResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Diagnostics")
	ret0, _ := ret[0].([]core.DiagnosticResult)
	return ret0
}

// Diagnostics indicates an expected call of Diagnostics.
func (mr *MockWalletMockRecorder) Diagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Diagnostics", reflect.TypeOf((*MockWallet)(nil).Diagnostics))
}

// IsEmpty mocks base method.
func (m *MockWallet) IsEmpty() (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsEmpty")
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsEmpty indicates an expected call of IsEmpty.
func (mr *MockWalletMockRecorder) IsEmpty() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsEmpty", reflect.TypeOf((*MockWallet)(nil).IsEmpty))
}

// List mocks base method.
func (m *MockWallet) List(ctx context.Context, holderDID did.DID) ([]vc.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx, holderDID)
	ret0, _ := ret[0].([]vc.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockWalletMockRecorder) List(ctx, holderDID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockWallet)(nil).List), ctx, holderDID)
}

// Put mocks base method.
func (m *MockWallet) Put(ctx context.Context, credentials ...vc.VerifiableCredential) error {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range credentials {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Put", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Put indicates an expected call of Put.
func (mr *MockWalletMockRecorder) Put(ctx any, credentials ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx}, credentials...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockWallet)(nil).Put), varargs...)
}
