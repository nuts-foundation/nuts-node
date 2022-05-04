// Code generated by MockGen. DO NOT EDIT.
// Source: network/dag/interface.go

// Package dag is a generated GoMock package.
package dag

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
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

// FindBetween mocks base method.
func (m *MockState) FindBetween(ctx context.Context, startInclusive, endExclusive time.Time) ([]Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindBetween", ctx, startInclusive, endExclusive)
	ret0, _ := ret[0].([]Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindBetween indicates an expected call of FindBetween.
func (mr *MockStateMockRecorder) FindBetween(ctx, startInclusive, endExclusive interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindBetween", reflect.TypeOf((*MockState)(nil).FindBetween), ctx, startInclusive, endExclusive)
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

// GetByPayloadHash mocks base method.
func (m *MockState) GetByPayloadHash(ctx context.Context, payloadHash hash.SHA256Hash) ([]Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByPayloadHash", ctx, payloadHash)
	ret0, _ := ret[0].([]Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByPayloadHash indicates an expected call of GetByPayloadHash.
func (mr *MockStateMockRecorder) GetByPayloadHash(ctx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByPayloadHash", reflect.TypeOf((*MockState)(nil).GetByPayloadHash), ctx, payloadHash)
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

// PayloadHashes mocks base method.
func (m *MockState) PayloadHashes(ctx context.Context, visitor func(hash.SHA256Hash) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PayloadHashes", ctx, visitor)
	ret0, _ := ret[0].(error)
	return ret0
}

// PayloadHashes indicates an expected call of PayloadHashes.
func (mr *MockStateMockRecorder) PayloadHashes(ctx, visitor interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PayloadHashes", reflect.TypeOf((*MockState)(nil).PayloadHashes), ctx, visitor)
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

// RegisterPayloadObserver mocks base method.
func (m *MockState) RegisterPayloadObserver(observer PayloadObserver, transactional bool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterPayloadObserver", observer, transactional)
}

// RegisterPayloadObserver indicates an expected call of RegisterPayloadObserver.
func (mr *MockStateMockRecorder) RegisterPayloadObserver(observer, transactional interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterPayloadObserver", reflect.TypeOf((*MockState)(nil).RegisterPayloadObserver), observer, transactional)
}

// RegisterTransactionObserver mocks base method.
func (m *MockState) RegisterTransactionObserver(observer Observer, transactional bool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterTransactionObserver", observer, transactional)
}

// RegisterTransactionObserver indicates an expected call of RegisterTransactionObserver.
func (mr *MockStateMockRecorder) RegisterTransactionObserver(observer, transactional interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterTransactionObserver", reflect.TypeOf((*MockState)(nil).RegisterTransactionObserver), observer, transactional)
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

// Statistics mocks base method.
func (m *MockState) Statistics(ctx context.Context) Statistics {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Statistics", ctx)
	ret0, _ := ret[0].(Statistics)
	return ret0
}

// Statistics indicates an expected call of Statistics.
func (mr *MockStateMockRecorder) Statistics(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Statistics", reflect.TypeOf((*MockState)(nil).Statistics), ctx)
}

// Subscribe mocks base method.
func (m *MockState) Subscribe(eventType EventType, payloadType string, receiver Receiver) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Subscribe", eventType, payloadType, receiver)
}

// Subscribe indicates an expected call of Subscribe.
func (mr *MockStateMockRecorder) Subscribe(eventType, payloadType, receiver interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockState)(nil).Subscribe), eventType, payloadType, receiver)
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

// Walk mocks base method.
func (m *MockState) Walk(ctx context.Context, visitor Visitor, startAt hash.SHA256Hash) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Walk", ctx, visitor, startAt)
	ret0, _ := ret[0].(error)
	return ret0
}

// Walk indicates an expected call of Walk.
func (mr *MockStateMockRecorder) Walk(ctx, visitor, startAt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Walk", reflect.TypeOf((*MockState)(nil).Walk), ctx, visitor, startAt)
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

// MockPublisher is a mock of Publisher interface.
type MockPublisher struct {
	ctrl     *gomock.Controller
	recorder *MockPublisherMockRecorder
}

// MockPublisherMockRecorder is the mock recorder for MockPublisher.
type MockPublisherMockRecorder struct {
	mock *MockPublisher
}

// NewMockPublisher creates a new mock instance.
func NewMockPublisher(ctrl *gomock.Controller) *MockPublisher {
	mock := &MockPublisher{ctrl: ctrl}
	mock.recorder = &MockPublisherMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPublisher) EXPECT() *MockPublisherMockRecorder {
	return m.recorder
}

// ConfigureCallbacks mocks base method.
func (m *MockPublisher) ConfigureCallbacks(state State) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ConfigureCallbacks", state)
}

// ConfigureCallbacks indicates an expected call of ConfigureCallbacks.
func (mr *MockPublisherMockRecorder) ConfigureCallbacks(state interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigureCallbacks", reflect.TypeOf((*MockPublisher)(nil).ConfigureCallbacks), state)
}

// Start mocks base method.
func (m *MockPublisher) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockPublisherMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockPublisher)(nil).Start))
}

// Subscribe mocks base method.
func (m *MockPublisher) Subscribe(eventType EventType, payloadType string, receiver Receiver) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Subscribe", eventType, payloadType, receiver)
}

// Subscribe indicates an expected call of Subscribe.
func (mr *MockPublisherMockRecorder) Subscribe(eventType, payloadType, receiver interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockPublisher)(nil).Subscribe), eventType, payloadType, receiver)
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

// IsPayloadPresent mocks base method.
func (m *MockPayloadStore) IsPayloadPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsPayloadPresent", ctx, payloadHash)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsPayloadPresent indicates an expected call of IsPayloadPresent.
func (mr *MockPayloadStoreMockRecorder) IsPayloadPresent(ctx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsPayloadPresent", reflect.TypeOf((*MockPayloadStore)(nil).IsPayloadPresent), ctx, payloadHash)
}

// ReadPayload mocks base method.
func (m *MockPayloadStore) ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadPayload", ctx, payloadHash)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadPayload indicates an expected call of ReadPayload.
func (mr *MockPayloadStoreMockRecorder) ReadPayload(ctx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadPayload", reflect.TypeOf((*MockPayloadStore)(nil).ReadPayload), ctx, payloadHash)
}

// WritePayload mocks base method.
func (m *MockPayloadStore) WritePayload(ctx context.Context, payloadHash hash.SHA256Hash, data []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WritePayload", ctx, payloadHash, data)
	ret0, _ := ret[0].(error)
	return ret0
}

// WritePayload indicates an expected call of WritePayload.
func (mr *MockPayloadStoreMockRecorder) WritePayload(ctx, payloadHash, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WritePayload", reflect.TypeOf((*MockPayloadStore)(nil).WritePayload), ctx, payloadHash, data)
}

// MockPayloadWriter is a mock of PayloadWriter interface.
type MockPayloadWriter struct {
	ctrl     *gomock.Controller
	recorder *MockPayloadWriterMockRecorder
}

// MockPayloadWriterMockRecorder is the mock recorder for MockPayloadWriter.
type MockPayloadWriterMockRecorder struct {
	mock *MockPayloadWriter
}

// NewMockPayloadWriter creates a new mock instance.
func NewMockPayloadWriter(ctrl *gomock.Controller) *MockPayloadWriter {
	mock := &MockPayloadWriter{ctrl: ctrl}
	mock.recorder = &MockPayloadWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPayloadWriter) EXPECT() *MockPayloadWriterMockRecorder {
	return m.recorder
}

// WritePayload mocks base method.
func (m *MockPayloadWriter) WritePayload(ctx context.Context, transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WritePayload", ctx, transaction, payloadHash, data)
	ret0, _ := ret[0].(error)
	return ret0
}

// WritePayload indicates an expected call of WritePayload.
func (mr *MockPayloadWriterMockRecorder) WritePayload(ctx, transaction, payloadHash, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WritePayload", reflect.TypeOf((*MockPayloadWriter)(nil).WritePayload), ctx, transaction, payloadHash, data)
}

// MockPayloadReader is a mock of PayloadReader interface.
type MockPayloadReader struct {
	ctrl     *gomock.Controller
	recorder *MockPayloadReaderMockRecorder
}

// MockPayloadReaderMockRecorder is the mock recorder for MockPayloadReader.
type MockPayloadReaderMockRecorder struct {
	mock *MockPayloadReader
}

// NewMockPayloadReader creates a new mock instance.
func NewMockPayloadReader(ctrl *gomock.Controller) *MockPayloadReader {
	mock := &MockPayloadReader{ctrl: ctrl}
	mock.recorder = &MockPayloadReaderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPayloadReader) EXPECT() *MockPayloadReaderMockRecorder {
	return m.recorder
}

// IsPayloadPresent mocks base method.
func (m *MockPayloadReader) IsPayloadPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsPayloadPresent", ctx, payloadHash)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsPayloadPresent indicates an expected call of IsPayloadPresent.
func (mr *MockPayloadReaderMockRecorder) IsPayloadPresent(ctx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsPayloadPresent", reflect.TypeOf((*MockPayloadReader)(nil).IsPayloadPresent), ctx, payloadHash)
}

// ReadPayload mocks base method.
func (m *MockPayloadReader) ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadPayload", ctx, payloadHash)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadPayload indicates an expected call of ReadPayload.
func (mr *MockPayloadReaderMockRecorder) ReadPayload(ctx, payloadHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadPayload", reflect.TypeOf((*MockPayloadReader)(nil).ReadPayload), ctx, payloadHash)
}
