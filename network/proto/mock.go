// Code generated by MockGen. DO NOT EDIT.
// Source: network/proto/interface.go

// Package proto is a generated GoMock package.
package proto

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	core "github.com/nuts-foundation/nuts-node/core"
	dag "github.com/nuts-foundation/nuts-node/network/dag"
	p2p "github.com/nuts-foundation/nuts-node/network/p2p"
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
func (m *MockProtocol) Configure(p2pNetwork p2p.Adapter, graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, verifier dag.TransactionSignatureVerifier, advertHashesInterval time.Duration, peerID p2p.PeerID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Configure", p2pNetwork, graph, publisher, payloadStore, verifier, advertHashesInterval, peerID)
}

// Configure indicates an expected call of Configure.
func (mr *MockProtocolMockRecorder) Configure(p2pNetwork, graph, publisher, payloadStore, verifier, advertHashesInterval, peerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockProtocol)(nil).Configure), p2pNetwork, graph, publisher, payloadStore, verifier, advertHashesInterval, peerID)
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

// Start mocks base method.
func (m *MockProtocol) Start() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Start")
}

// Start indicates an expected call of Start.
func (mr *MockProtocolMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockProtocol)(nil).Start))
}

// Stop mocks base method.
func (m *MockProtocol) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop.
func (mr *MockProtocolMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockProtocol)(nil).Stop))
}

// MockPeerOmnihashQueue is a mock of PeerOmnihashQueue interface.
type MockPeerOmnihashQueue struct {
	ctrl     *gomock.Controller
	recorder *MockPeerOmnihashQueueMockRecorder
}

// MockPeerOmnihashQueueMockRecorder is the mock recorder for MockPeerOmnihashQueue.
type MockPeerOmnihashQueueMockRecorder struct {
	mock *MockPeerOmnihashQueue
}

// NewMockPeerOmnihashQueue creates a new mock instance.
func NewMockPeerOmnihashQueue(ctrl *gomock.Controller) *MockPeerOmnihashQueue {
	mock := &MockPeerOmnihashQueue{ctrl: ctrl}
	mock.recorder = &MockPeerOmnihashQueueMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPeerOmnihashQueue) EXPECT() *MockPeerOmnihashQueueMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockPeerOmnihashQueue) Get() *PeerOmnihash {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get")
	ret0, _ := ret[0].(*PeerOmnihash)
	return ret0
}

// Get indicates an expected call of Get.
func (mr *MockPeerOmnihashQueueMockRecorder) Get() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockPeerOmnihashQueue)(nil).Get))
}
