// Code generated by MockGen. DO NOT EDIT.
// Source: network/interface.go

// Package network is a generated GoMock package.
package network

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
	dag "github.com/nuts-foundation/nuts-node/network/dag"
	transport "github.com/nuts-foundation/nuts-node/network/transport"
)

// MockTransactions is a mock of Transactions interface.
type MockTransactions struct {
	ctrl     *gomock.Controller
	recorder *MockTransactionsMockRecorder
}

// MockTransactionsMockRecorder is the mock recorder for MockTransactions.
type MockTransactionsMockRecorder struct {
	mock *MockTransactions
}

// NewMockTransactions creates a new mock instance.
func NewMockTransactions(ctrl *gomock.Controller) *MockTransactions {
	mock := &MockTransactions{ctrl: ctrl}
	mock.recorder = &MockTransactionsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTransactions) EXPECT() *MockTransactionsMockRecorder {
	return m.recorder
}

// CreateTransaction mocks base method.
func (m *MockTransactions) CreateTransaction(spec Template) (dag.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTransaction", spec)
	ret0, _ := ret[0].(dag.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTransaction indicates an expected call of CreateTransaction.
func (mr *MockTransactionsMockRecorder) CreateTransaction(spec interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTransaction", reflect.TypeOf((*MockTransactions)(nil).CreateTransaction), spec)
}

// GetTransaction mocks base method.
func (m *MockTransactions) GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTransaction", transactionRef)
	ret0, _ := ret[0].(dag.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTransaction indicates an expected call of GetTransaction.
func (mr *MockTransactionsMockRecorder) GetTransaction(transactionRef interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTransaction", reflect.TypeOf((*MockTransactions)(nil).GetTransaction), transactionRef)
}

// GetTransactionPayload mocks base method.
func (m *MockTransactions) GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTransactionPayload", transactionRef)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTransactionPayload indicates an expected call of GetTransactionPayload.
func (mr *MockTransactionsMockRecorder) GetTransactionPayload(transactionRef interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTransactionPayload", reflect.TypeOf((*MockTransactions)(nil).GetTransactionPayload), transactionRef)
}

// ListTransactions mocks base method.
func (m *MockTransactions) ListTransactions() ([]dag.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTransactions")
	ret0, _ := ret[0].([]dag.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListTransactions indicates an expected call of ListTransactions.
func (mr *MockTransactionsMockRecorder) ListTransactions() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTransactions", reflect.TypeOf((*MockTransactions)(nil).ListTransactions))
}

// PeerDiagnostics mocks base method.
func (m *MockTransactions) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PeerDiagnostics")
	ret0, _ := ret[0].(map[transport.PeerID]transport.Diagnostics)
	return ret0
}

// PeerDiagnostics indicates an expected call of PeerDiagnostics.
func (mr *MockTransactionsMockRecorder) PeerDiagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PeerDiagnostics", reflect.TypeOf((*MockTransactions)(nil).PeerDiagnostics))
}

// Reprocess mocks base method.
func (m *MockTransactions) Reprocess(contentType string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Reprocess", contentType)
}

// Reprocess indicates an expected call of Reprocess.
func (mr *MockTransactionsMockRecorder) Reprocess(contentType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reprocess", reflect.TypeOf((*MockTransactions)(nil).Reprocess), contentType)
}

// Subscribe mocks base method.
func (m *MockTransactions) Subscribe(eventType EventType, payloadType string, receiver Receiver) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Subscribe", eventType, payloadType, receiver)
}

// Subscribe indicates an expected call of Subscribe.
func (mr *MockTransactionsMockRecorder) Subscribe(eventType, payloadType, receiver interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockTransactions)(nil).Subscribe), eventType, payloadType, receiver)
}

// Walk mocks base method.
func (m *MockTransactions) Walk(visitor dag.Visitor) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Walk", visitor)
	ret0, _ := ret[0].(error)
	return ret0
}

// Walk indicates an expected call of Walk.
func (mr *MockTransactionsMockRecorder) Walk(visitor interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Walk", reflect.TypeOf((*MockTransactions)(nil).Walk), visitor)
}
