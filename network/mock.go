// Code generated by MockGen. DO NOT EDIT.
// Source: network/interface.go

// Package network is a generated GoMock package.
package network

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	crypto "github.com/nuts-foundation/nuts-node/crypto"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
	dag "github.com/nuts-foundation/nuts-node/network/dag"
	types "github.com/nuts-foundation/nuts-node/network/protocol/types"
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
func (m *MockTransactions) CreateTransaction(payloadType string, payload []byte, key crypto.Key, attachKey bool, timestamp time.Time, additionalPrevs []hash.SHA256Hash) (dag.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTransaction", payloadType, payload, key, attachKey, timestamp, additionalPrevs)
	ret0, _ := ret[0].(dag.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTransaction indicates an expected call of CreateTransaction.
func (mr *MockTransactionsMockRecorder) CreateTransaction(payloadType, payload, key, attachKey, timestamp, additionalPrevs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTransaction", reflect.TypeOf((*MockTransactions)(nil).CreateTransaction), payloadType, payload, key, attachKey, timestamp, additionalPrevs)
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
func (m *MockTransactions) PeerDiagnostics() map[types.PeerID]types.Diagnostics {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PeerDiagnostics")
	ret0, _ := ret[0].(map[types.PeerID]types.Diagnostics)
	return ret0
}

// PeerDiagnostics indicates an expected call of PeerDiagnostics.
func (mr *MockTransactionsMockRecorder) PeerDiagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PeerDiagnostics", reflect.TypeOf((*MockTransactions)(nil).PeerDiagnostics))
}

// Subscribe mocks base method.
func (m *MockTransactions) Subscribe(payloadType string, receiver dag.Receiver) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Subscribe", payloadType, receiver)
}

// Subscribe indicates an expected call of Subscribe.
func (mr *MockTransactionsMockRecorder) Subscribe(payloadType, receiver interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockTransactions)(nil).Subscribe), payloadType, receiver)
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
