// Code generated by MockGen. DO NOT EDIT.
// Source: network/transport/grpc/authenticator.go
//
// Generated by this command:
//
//	mockgen -destination=network/transport/grpc/authenticator_mock.go -package=grpc -source=network/transport/grpc/authenticator.go
//

// Package grpc is a generated GoMock package.
package grpc

import (
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	transport "github.com/nuts-foundation/nuts-node/network/transport"
	gomock "go.uber.org/mock/gomock"
)

// MockAuthenticator is a mock of Authenticator interface.
type MockAuthenticator struct {
	ctrl     *gomock.Controller
	recorder *MockAuthenticatorMockRecorder
	isgomock struct{}
}

// MockAuthenticatorMockRecorder is the mock recorder for MockAuthenticator.
type MockAuthenticatorMockRecorder struct {
	mock *MockAuthenticator
}

// NewMockAuthenticator creates a new mock instance.
func NewMockAuthenticator(ctrl *gomock.Controller) *MockAuthenticator {
	mock := &MockAuthenticator{ctrl: ctrl}
	mock.recorder = &MockAuthenticatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthenticator) EXPECT() *MockAuthenticatorMockRecorder {
	return m.recorder
}

// Authenticate mocks base method.
func (m *MockAuthenticator) Authenticate(nodeDID did.DID, peer transport.Peer) (transport.Peer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Authenticate", nodeDID, peer)
	ret0, _ := ret[0].(transport.Peer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Authenticate indicates an expected call of Authenticate.
func (mr *MockAuthenticatorMockRecorder) Authenticate(nodeDID, peer any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authenticate", reflect.TypeOf((*MockAuthenticator)(nil).Authenticate), nodeDID, peer)
}
