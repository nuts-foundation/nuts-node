// Code generated by MockGen. DO NOT EDIT.
// Source: network/transport/connection_manager.go

// Package transport is a generated GoMock package.
package transport

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	did "github.com/nuts-foundation/go-did/did"
	core "github.com/nuts-foundation/nuts-node/core"
)

// MockConnectionManager is a mock of ConnectionManager interface.
type MockConnectionManager struct {
	ctrl     *gomock.Controller
	recorder *MockConnectionManagerMockRecorder
}

// MockConnectionManagerMockRecorder is the mock recorder for MockConnectionManager.
type MockConnectionManagerMockRecorder struct {
	mock *MockConnectionManager
}

// NewMockConnectionManager creates a new mock instance.
func NewMockConnectionManager(ctrl *gomock.Controller) *MockConnectionManager {
	mock := &MockConnectionManager{ctrl: ctrl}
	mock.recorder = &MockConnectionManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnectionManager) EXPECT() *MockConnectionManagerMockRecorder {
	return m.recorder
}

// Connect mocks base method.
func (m *MockConnectionManager) Connect(peerAddress string, peerDID did.DID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Connect", peerAddress, peerDID)
}

// Connect indicates an expected call of Connect.
func (mr *MockConnectionManagerMockRecorder) Connect(peerAddress, peerDID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Connect", reflect.TypeOf((*MockConnectionManager)(nil).Connect), peerAddress, peerDID)
}

// Diagnostics mocks base method.
func (m *MockConnectionManager) Diagnostics() []core.DiagnosticResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Diagnostics")
	ret0, _ := ret[0].([]core.DiagnosticResult)
	return ret0
}

// Diagnostics indicates an expected call of Diagnostics.
func (mr *MockConnectionManagerMockRecorder) Diagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Diagnostics", reflect.TypeOf((*MockConnectionManager)(nil).Diagnostics))
}

// Peers mocks base method.
func (m *MockConnectionManager) Peers() []Peer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Peers")
	ret0, _ := ret[0].([]Peer)
	return ret0
}

// Peers indicates an expected call of Peers.
func (mr *MockConnectionManagerMockRecorder) Peers() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Peers", reflect.TypeOf((*MockConnectionManager)(nil).Peers))
}

// RegisterObserver mocks base method.
func (m *MockConnectionManager) RegisterObserver(callback StreamStateObserverFunc) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterObserver", callback)
}

// RegisterObserver indicates an expected call of RegisterObserver.
func (mr *MockConnectionManagerMockRecorder) RegisterObserver(callback interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterObserver", reflect.TypeOf((*MockConnectionManager)(nil).RegisterObserver), callback)
}

// Start mocks base method.
func (m *MockConnectionManager) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockConnectionManagerMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockConnectionManager)(nil).Start))
}

// Stop mocks base method.
func (m *MockConnectionManager) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop.
func (mr *MockConnectionManagerMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockConnectionManager)(nil).Stop))
}
