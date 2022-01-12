// Code generated by MockGen. DO NOT EDIT.
// Source: network/transport/grpc/connection.go

// Package grpc is a generated GoMock package.
package grpc

import (
	tls "crypto/tls"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	transport "github.com/nuts-foundation/nuts-node/network/transport"
	grpc "google.golang.org/grpc"
)

// MockConnection is a mock of Connection interface.
type MockConnection struct {
	ctrl     *gomock.Controller
	recorder *MockConnectionMockRecorder
}

// MockConnectionMockRecorder is the mock recorder for MockConnection.
type MockConnectionMockRecorder struct {
	mock *MockConnection
}

// NewMockConnection creates a new mock instance.
func NewMockConnection(ctrl *gomock.Controller) *MockConnection {
	mock := &MockConnection{ctrl: ctrl}
	mock.recorder = &MockConnectionMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnection) EXPECT() *MockConnectionMockRecorder {
	return m.recorder
}

// IsConnected mocks base method.
func (m *MockConnection) IsConnected() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsConnected")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsConnected indicates an expected call of IsConnected.
func (mr *MockConnectionMockRecorder) IsConnected() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsConnected", reflect.TypeOf((*MockConnection)(nil).IsConnected))
}

// Peer mocks base method.
func (m *MockConnection) Peer() transport.Peer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Peer")
	ret0, _ := ret[0].(transport.Peer)
	return ret0
}

// Peer indicates an expected call of Peer.
func (mr *MockConnectionMockRecorder) Peer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Peer", reflect.TypeOf((*MockConnection)(nil).Peer))
}

// Send mocks base method.
func (m *MockConnection) Send(protocol Protocol, envelope interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Send", protocol, envelope)
	ret0, _ := ret[0].(error)
	return ret0
}

// Send indicates an expected call of Send.
func (mr *MockConnectionMockRecorder) Send(protocol, envelope interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Send", reflect.TypeOf((*MockConnection)(nil).Send), protocol, envelope)
}

// disconnect mocks base method.
func (m *MockConnection) disconnect() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "disconnect")
}

// disconnect indicates an expected call of disconnect.
func (mr *MockConnectionMockRecorder) disconnect() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "disconnect", reflect.TypeOf((*MockConnection)(nil).disconnect))
}

// registerStream mocks base method.
func (m *MockConnection) registerStream(protocol Protocol, stream Stream) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "registerStream", protocol, stream)
	ret0, _ := ret[0].(bool)
	return ret0
}

// registerStream indicates an expected call of registerStream.
func (mr *MockConnectionMockRecorder) registerStream(protocol, stream interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "registerStream", reflect.TypeOf((*MockConnection)(nil).registerStream), protocol, stream)
}

// startConnecting mocks base method.
func (m *MockConnection) startConnecting(config *tls.Config, callback func(*grpc.ClientConn) bool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "startConnecting", config, callback)
}

// startConnecting indicates an expected call of startConnecting.
func (mr *MockConnectionMockRecorder) startConnecting(config, callback interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "startConnecting", reflect.TypeOf((*MockConnection)(nil).startConnecting), config, callback)
}

// stats mocks base method.
func (m *MockConnection) stats() transport.ConnectionStats {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "stats")
	ret0, _ := ret[0].(transport.ConnectionStats)
	return ret0
}

// stats indicates an expected call of stats.
func (mr *MockConnectionMockRecorder) stats() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "stats", reflect.TypeOf((*MockConnection)(nil).stats))
}

// stopConnecting mocks base method.
func (m *MockConnection) stopConnecting() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "stopConnecting")
}

// stopConnecting indicates an expected call of stopConnecting.
func (mr *MockConnectionMockRecorder) stopConnecting() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "stopConnecting", reflect.TypeOf((*MockConnection)(nil).stopConnecting))
}

// verifyOrSetPeerID mocks base method.
func (m *MockConnection) verifyOrSetPeerID(id transport.PeerID) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "verifyOrSetPeerID", id)
	ret0, _ := ret[0].(bool)
	return ret0
}

// verifyOrSetPeerID indicates an expected call of verifyOrSetPeerID.
func (mr *MockConnectionMockRecorder) verifyOrSetPeerID(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "verifyOrSetPeerID", reflect.TypeOf((*MockConnection)(nil).verifyOrSetPeerID), id)
}

// waitUntilDisconnected mocks base method.
func (m *MockConnection) waitUntilDisconnected() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "waitUntilDisconnected")
}

// waitUntilDisconnected indicates an expected call of waitUntilDisconnected.
func (mr *MockConnectionMockRecorder) waitUntilDisconnected() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "waitUntilDisconnected", reflect.TypeOf((*MockConnection)(nil).waitUntilDisconnected))
}
