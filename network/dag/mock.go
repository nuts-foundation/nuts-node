// Code generated by MockGen. DO NOT EDIT.
// Source: network/dag/interface.go

// Package dag is a generated GoMock package.
package dag

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	go_stoabs "github.com/nuts-foundation/go-stoabs"
	core "github.com/nuts-foundation/nuts-node/core"
	hash "github.com/nuts-foundation/nuts-node/crypto/hash"
	tree "github.com/nuts-foundation/nuts-node/network/dag/tree"
)

// MockState is a mock of State interface.
type MockState struct {
	ctrl     *gomock.Controller
	recorder *MockStateMockRecorder
}

// MockStateMockRecorder is the mock recorder for MockState.
type MockStateMockRecorder struct {
	mock *MockState
}

// NewMockState creates a new mock instance.
func NewMockState(ctrl *gomock.Controller) *MockState {
	mock := &MockState{ctrl: ctrl}
	mock.recorder = &MockStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockState) EXPECT() *MockStateMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockState) Add(ctx context.Context, transactions Transaction, payload []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", ctx, transactions, payload)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockStateMockRecorder) Add(ctx, transactions, payload interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockState)(nil).Add), ctx, transactions, payload)
}

// Diagnostics mocks base method.
func (m *MockState) Diagnostics() []core.DiagnosticResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Diagnostics")
	ret0, _ := ret[0].([]core.DiagnosticResult)
	return ret0
}

// Diagnostics indicates an expected call of Diagnostics.
func (mr *MockStateMockRecorder) Diagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Diagnostics", reflect.TypeOf((*MockState)(nil).Diagnostics))
}

// FindBetweenLC mocks base method.
func (m *MockState) FindBetweenLC(ctx context.Context, startInclusive, endExclusive uint32) ([]Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindBetweenLC", ctx, startInclusive, endExclusive)
	ret0, _ := ret[0].([]Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindBetweenLC indicates an expected call of FindBetweenLC.
func (mr *MockStateMockRecorder) FindBetweenLC(ctx, startInclusive, endExclusive interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindBetweenLC", reflect.TypeOf((*MockState)(nil).FindBetweenLC), ctx, startInclusive, endExclusive)
}

// GetTransaction mocks base method.
func (m *MockState) GetTransaction(ctx context.Context, hash hash.SHA256Hash) (Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTransaction", ctx, hash)
	ret0, _ := ret[0].(Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTransaction indicates an expected call of GetTransaction.
func (mr *MockStateMockRecorder) GetTransaction(ctx, hash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTransaction", reflect.TypeOf((*MockState)(nil).GetTransaction), ctx, hash)
}

// Heads mocks base method.
func (m *MockState) Heads(ctx context.Context) []hash.SHA256Hash {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Heads", ctx)
	ret0, _ := ret[0].([]hash.SHA256Hash)
	return ret0
}

// Heads indicates an expected call of Heads.
func (mr *MockStateMockRecorder) Heads(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Heads", reflect.TypeOf((*MockState)(nil).Heads), ctx)
}

// IBLT mocks base method.
func (m *MockState) IBLT(ctx context.Context, reqClock uint32) (tree.Iblt, uint32) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IBLT", ctx, reqClock)
	ret0, _ := ret[0].(tree.Iblt)
	ret1, _ := ret[1].(uint32)
	return ret0, ret1
}

// IBLT indicates an expected call of IBLT.
func (mr *MockStateMockRecorder) IBLT(ctx, reqClock interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IBLT", reflect.TypeOf((*MockState)(nil).IBLT), ctx, reqClock)
}

// IsPayloadPresent mocks base method.
func (m *MockState) IsPayloadPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsPayloadPresent", ctx, payloadHash)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsPayloadPresent indicates an expected call of IsPayloadPresent.
func (mr *MockStateMockRecorder) IsPayloadPresent(ctx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsPayloadPresent", reflect.TypeOf((*MockState)(nil).IsPayloadPresent), ctx, payloadHash)
}

// IsPresent mocks base method.
func (m *MockState) IsPresent(arg0 context.Context, arg1 hash.SHA256Hash) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsPresent", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsPresent indicates an expected call of IsPresent.
func (mr *MockStateMockRecorder) IsPresent(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsPresent", reflect.TypeOf((*MockState)(nil).IsPresent), arg0, arg1)
}

// Migrate mocks base method.
func (m *MockState) Migrate() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Migrate")
	ret0, _ := ret[0].(error)
	return ret0
}

// Migrate indicates an expected call of Migrate.
func (mr *MockStateMockRecorder) Migrate() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Migrate", reflect.TypeOf((*MockState)(nil).Migrate))
}

// Notifier mocks base method.
func (m *MockState) Notifier(name string, receiver ReceiverFn, filters ...NotifierOption) (Notifier, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{name, receiver}
	for _, a := range filters {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Notifier", varargs...)
	ret0, _ := ret[0].(Notifier)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Notifier indicates an expected call of Notifier.
func (mr *MockStateMockRecorder) Notifier(name, receiver interface{}, filters ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{name, receiver}, filters...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Notifier", reflect.TypeOf((*MockState)(nil).Notifier), varargs...)
}

// ReadPayload mocks base method.
func (m *MockState) ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadPayload", ctx, payloadHash)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadPayload indicates an expected call of ReadPayload.
func (mr *MockStateMockRecorder) ReadPayload(ctx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadPayload", reflect.TypeOf((*MockState)(nil).ReadPayload), ctx, payloadHash)
}

// Shutdown mocks base method.
func (m *MockState) Shutdown() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Shutdown")
	ret0, _ := ret[0].(error)
	return ret0
}

// Shutdown indicates an expected call of Shutdown.
func (mr *MockStateMockRecorder) Shutdown() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Shutdown", reflect.TypeOf((*MockState)(nil).Shutdown))
}

// Start mocks base method.
func (m *MockState) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockStateMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockState)(nil).Start))
}

// Verify mocks base method.
func (m *MockState) Verify(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockStateMockRecorder) Verify(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockState)(nil).Verify), ctx)
}

// WritePayload mocks base method.
func (m *MockState) WritePayload(ctx context.Context, transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WritePayload", ctx, transaction, payloadHash, data)
	ret0, _ := ret[0].(error)
	return ret0
}

// WritePayload indicates an expected call of WritePayload.
func (mr *MockStateMockRecorder) WritePayload(ctx, transaction, payloadHash, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WritePayload", reflect.TypeOf((*MockState)(nil).WritePayload), ctx, transaction, payloadHash, data)
}

// XOR mocks base method.
func (m *MockState) XOR(ctx context.Context, reqClock uint32) (hash.SHA256Hash, uint32) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "XOR", ctx, reqClock)
	ret0, _ := ret[0].(hash.SHA256Hash)
	ret1, _ := ret[1].(uint32)
	return ret0, ret1
}

// XOR indicates an expected call of XOR.
func (mr *MockStateMockRecorder) XOR(ctx, reqClock interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "XOR", reflect.TypeOf((*MockState)(nil).XOR), ctx, reqClock)
}

// MockPayloadStore is a mock of PayloadStore interface.
type MockPayloadStore struct {
	ctrl     *gomock.Controller
	recorder *MockPayloadStoreMockRecorder
}

// MockPayloadStoreMockRecorder is the mock recorder for MockPayloadStore.
type MockPayloadStoreMockRecorder struct {
	mock *MockPayloadStore
}

// NewMockPayloadStore creates a new mock instance.
func NewMockPayloadStore(ctrl *gomock.Controller) *MockPayloadStore {
	mock := &MockPayloadStore{ctrl: ctrl}
	mock.recorder = &MockPayloadStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPayloadStore) EXPECT() *MockPayloadStoreMockRecorder {
	return m.recorder
}

// isPayloadPresent mocks base method.
func (m *MockPayloadStore) isPayloadPresent(tx go_stoabs.ReadTx, payloadHash hash.SHA256Hash) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "isPayloadPresent", tx, payloadHash)
	ret0, _ := ret[0].(bool)
	return ret0
}

// isPayloadPresent indicates an expected call of isPayloadPresent.
func (mr *MockPayloadStoreMockRecorder) isPayloadPresent(tx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "isPayloadPresent", reflect.TypeOf((*MockPayloadStore)(nil).isPayloadPresent), tx, payloadHash)
}

// readPayload mocks base method.
func (m *MockPayloadStore) readPayload(tx go_stoabs.ReadTx, payloadHash hash.SHA256Hash) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "readPayload", tx, payloadHash)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// readPayload indicates an expected call of readPayload.
func (mr *MockPayloadStoreMockRecorder) readPayload(tx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "readPayload", reflect.TypeOf((*MockPayloadStore)(nil).readPayload), tx, payloadHash)
}

// writePayload mocks base method.
func (m *MockPayloadStore) writePayload(tx go_stoabs.WriteTx, payloadHash hash.SHA256Hash, data []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "writePayload", tx, payloadHash, data)
	ret0, _ := ret[0].(error)
	return ret0
}

// writePayload indicates an expected call of writePayload.
func (mr *MockPayloadStoreMockRecorder) writePayload(tx, payloadHash, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "writePayload", reflect.TypeOf((*MockPayloadStore)(nil).writePayload), tx, payloadHash, data)
}
