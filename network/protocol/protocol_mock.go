// Code generated by MockGen. DO NOT EDIT.
// Source: network/protocol/protocol.go

// Package protocol is a generated GoMock package.
package protocol

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	core "github.com/nuts-foundation/nuts-node/core"
	types "github.com/nuts-foundation/nuts-node/network/protocol/types"
)

// MockProtocol is a mock of Protocol interface.
type MockProtocol struct {
	ctrl     *gomock.Controller
	recorder *MockProtocolMockRecorder
}

// MockProtocolMockRecorder is the mock recorder for MockProtocol.
type MockProtocolMockRecorder struct {
	mock *MockProtocol
}

// NewMockProtocol creates a new mock instance.
func NewMockProtocol(ctrl *gomock.Controller) *MockProtocol {
	mock := &MockProtocol{ctrl: ctrl}
	mock.recorder = &MockProtocolMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProtocol) EXPECT() *MockProtocolMockRecorder {
	return m.recorder
}

// Configure mocks base method.
func (m *MockProtocol) Configure() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure")
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure.
func (mr *MockProtocolMockRecorder) Configure() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockProtocol)(nil).Configure))
}

// Connect mocks base method.
func (m *MockProtocol) Connect(peerAddress string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Connect", peerAddress)
}

// Connect indicates an expected call of Connect.
func (mr *MockProtocolMockRecorder) Connect(peerAddress interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Connect", reflect.TypeOf((*MockProtocol)(nil).Connect), peerAddress)
}

// Diagnostics mocks base method.
func (m *MockProtocol) Diagnostics() []core.DiagnosticResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Diagnostics")
	ret0, _ := ret[0].([]core.DiagnosticResult)
	return ret0
}

// Diagnostics indicates an expected call of Diagnostics.
func (mr *MockProtocolMockRecorder) Diagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Diagnostics", reflect.TypeOf((*MockProtocol)(nil).Diagnostics))
}

// PeerDiagnostics mocks base method.
func (m *MockProtocol) PeerDiagnostics() map[types.PeerID]types.Diagnostics {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PeerDiagnostics")
	ret0, _ := ret[0].(map[types.PeerID]types.Diagnostics)
	return ret0
}

// PeerDiagnostics indicates an expected call of PeerDiagnostics.
func (mr *MockProtocolMockRecorder) PeerDiagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PeerDiagnostics", reflect.TypeOf((*MockProtocol)(nil).PeerDiagnostics))
}

// Peers mocks base method.
func (m *MockProtocol) Peers() []types.Peer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Peers")
	ret0, _ := ret[0].([]types.Peer)
	return ret0
}

// Peers indicates an expected call of Peers.
func (mr *MockProtocolMockRecorder) Peers() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Peers", reflect.TypeOf((*MockProtocol)(nil).Peers))
}

// Start mocks base method.
func (m *MockProtocol) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockProtocolMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockProtocol)(nil).Start))
}

// Stop mocks base method.
func (m *MockProtocol) Stop() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stop")
	ret0, _ := ret[0].(error)
	return ret0
}

// Stop indicates an expected call of Stop.
func (mr *MockProtocolMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockProtocol)(nil).Stop))
}
