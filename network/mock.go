// Code generated by MockGen. DO NOT EDIT.
// Source: network/interface.go
//
// Generated by this command:
//
//	mockgen -destination=network/mock.go -package=network -source=network/interface.go
//

// Package network is a generated GoMock package.
package network

import (
	context "context"
	reflect "reflect"

	did "github.com/nuts-foundation/go-did/did"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
	dag "github.com/nuts-foundation/nuts-node/network/dag"
	transport "github.com/nuts-foundation/nuts-node/network/transport"
	gomock "go.uber.org/mock/gomock"
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

// AddressBook mocks base method.
func (m *MockTransactions) AddressBook() []transport.Contact {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddressBook")
	ret0, _ := ret[0].([]transport.Contact)
	return ret0
}

// AddressBook indicates an expected call of AddressBook.
func (mr *MockTransactionsMockRecorder) AddressBook() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddressBook", reflect.TypeOf((*MockTransactions)(nil).AddressBook))
}

// CreateTransaction mocks base method.
func (m *MockTransactions) CreateTransaction(ctx context.Context, spec Template) (dag.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateTransaction", ctx, spec)
	ret0, _ := ret[0].(dag.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateTransaction indicates an expected call of CreateTransaction.
func (mr *MockTransactionsMockRecorder) CreateTransaction(ctx, spec any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateTransaction", reflect.TypeOf((*MockTransactions)(nil).CreateTransaction), ctx, spec)
}

// Disabled mocks base method.
func (m *MockTransactions) Disabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Disabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Disabled indicates an expected call of Disabled.
func (mr *MockTransactionsMockRecorder) Disabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Disabled", reflect.TypeOf((*MockTransactions)(nil).Disabled))
}

// DiscoverServices mocks base method.
func (m *MockTransactions) DiscoverServices(updatedDID did.DID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DiscoverServices", updatedDID)
}

// DiscoverServices indicates an expected call of DiscoverServices.
func (mr *MockTransactionsMockRecorder) DiscoverServices(updatedDID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DiscoverServices", reflect.TypeOf((*MockTransactions)(nil).DiscoverServices), updatedDID)
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
func (mr *MockTransactionsMockRecorder) GetTransaction(transactionRef any) *gomock.Call {
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
func (mr *MockTransactionsMockRecorder) GetTransactionPayload(transactionRef any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTransactionPayload", reflect.TypeOf((*MockTransactions)(nil).GetTransactionPayload), transactionRef)
}

// ListTransactionsInRange mocks base method.
func (m *MockTransactions) ListTransactionsInRange(startInclusive, endExclusive uint32) ([]dag.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTransactionsInRange", startInclusive, endExclusive)
	ret0, _ := ret[0].([]dag.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListTransactionsInRange indicates an expected call of ListTransactionsInRange.
func (mr *MockTransactionsMockRecorder) ListTransactionsInRange(startInclusive, endExclusive any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTransactionsInRange", reflect.TypeOf((*MockTransactions)(nil).ListTransactionsInRange), startInclusive, endExclusive)
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
func (m *MockTransactions) Reprocess(ctx context.Context, contentType string) (*ReprocessReport, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Reprocess", ctx, contentType)
	ret0, _ := ret[0].(*ReprocessReport)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Reprocess indicates an expected call of Reprocess.
func (mr *MockTransactionsMockRecorder) Reprocess(ctx, contentType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reprocess", reflect.TypeOf((*MockTransactions)(nil).Reprocess), ctx, contentType)
}

// Subscribe mocks base method.
func (m *MockTransactions) Subscribe(name string, receiver dag.ReceiverFn, filters ...SubscriberOption) error {
	m.ctrl.T.Helper()
	varargs := []any{name, receiver}
	for _, a := range filters {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Subscribe", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Subscribe indicates an expected call of Subscribe.
func (mr *MockTransactionsMockRecorder) Subscribe(name, receiver any, filters ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{name, receiver}, filters...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockTransactions)(nil).Subscribe), varargs...)
}

// Subscribers mocks base method.
func (m *MockTransactions) Subscribers() []dag.Notifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Subscribers")
	ret0, _ := ret[0].([]dag.Notifier)
	return ret0
}

// Subscribers indicates an expected call of Subscribers.
func (mr *MockTransactionsMockRecorder) Subscribers() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribers", reflect.TypeOf((*MockTransactions)(nil).Subscribers))
}

// WithPersistency mocks base method.
func (m *MockTransactions) WithPersistency() SubscriberOption {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithPersistency")
	ret0, _ := ret[0].(SubscriberOption)
	return ret0
}

// WithPersistency indicates an expected call of WithPersistency.
func (mr *MockTransactionsMockRecorder) WithPersistency() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithPersistency", reflect.TypeOf((*MockTransactions)(nil).WithPersistency))
}
