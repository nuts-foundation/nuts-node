// Code generated by MockGen. DO NOT EDIT.
// Source: policy/interface.go
//
// Generated by this command:
//
//	mockgen -destination=policy/mock.go -package=policy -source=policy/interface.go
//

// Package policy is a generated GoMock package.
package policy

import (
	context "context"
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	pe "github.com/nuts-foundation/nuts-node/vcr/pe"
	gomock "go.uber.org/mock/gomock"
)

// MockPDPBackend is a mock of PDPBackend interface.
type MockPDPBackend struct {
	ctrl     *gomock.Controller
	recorder *MockPDPBackendMockRecorder
}

// MockPDPBackendMockRecorder is the mock recorder for MockPDPBackend.
type MockPDPBackendMockRecorder struct {
	mock *MockPDPBackend
}

// NewMockPDPBackend creates a new mock instance.
func NewMockPDPBackend(ctrl *gomock.Controller) *MockPDPBackend {
	mock := &MockPDPBackend{ctrl: ctrl}
	mock.recorder = &MockPDPBackendMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPDPBackend) EXPECT() *MockPDPBackendMockRecorder {
	return m.recorder
}

// PresentationDefinitions mocks base method.
func (m *MockPDPBackend) PresentationDefinitions(ctx context.Context, authorizer did.DID, scope string) (pe.WalletOwnerMapping, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PresentationDefinitions", ctx, authorizer, scope)
	ret0, _ := ret[0].(pe.WalletOwnerMapping)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PresentationDefinitions indicates an expected call of PresentationDefinitions.
func (mr *MockPDPBackendMockRecorder) PresentationDefinitions(ctx, authorizer, scope any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PresentationDefinitions", reflect.TypeOf((*MockPDPBackend)(nil).PresentationDefinitions), ctx, authorizer, scope)
}
