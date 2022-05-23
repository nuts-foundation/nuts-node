// Code generated by MockGen. DO NOT EDIT.
// Source: storage/interface.go

// Package storage is a generated GoMock package.
package storage

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	core "github.com/nuts-foundation/nuts-node/core"
)

// MockEngine is a mock of Engine interface.
type MockEngine struct {
	ctrl     *gomock.Controller
	recorder *MockEngineMockRecorder
}

// MockEngineMockRecorder is the mock recorder for MockEngine.
type MockEngineMockRecorder struct {
	mock *MockEngine
}

// NewMockEngine creates a new mock instance.
func NewMockEngine(ctrl *gomock.Controller) *MockEngine {
	mock := &MockEngine{ctrl: ctrl}
	mock.recorder = &MockEngineMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEngine) EXPECT() *MockEngineMockRecorder {
	return m.recorder
}

// Configure mocks base method.
func (m *MockEngine) Configure(config core.ServerConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure", config)
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure.
func (mr *MockEngineMockRecorder) Configure(config interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockEngine)(nil).Configure), config)
}

// GetKVStore mocks base method.
func (m *MockEngine) GetKVStore(namespace, name string) (KVStore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetKVStore", namespace, name)
	ret0, _ := ret[0].(KVStore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetKVStore indicates an expected call of GetKVStore.
func (mr *MockEngineMockRecorder) GetKVStore(namespace, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetKVStore", reflect.TypeOf((*MockEngine)(nil).GetKVStore), namespace, name)
}

// Shutdown mocks base method.
func (m *MockEngine) Shutdown() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Shutdown")
	ret0, _ := ret[0].(error)
	return ret0
}

// Shutdown indicates an expected call of Shutdown.
func (mr *MockEngineMockRecorder) Shutdown() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Shutdown", reflect.TypeOf((*MockEngine)(nil).Shutdown))
}

// Start mocks base method.
func (m *MockEngine) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockEngineMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockEngine)(nil).Start))
}

// MockProvider is a mock of Provider interface.
type MockProvider struct {
	ctrl     *gomock.Controller
	recorder *MockProviderMockRecorder
}

// MockProviderMockRecorder is the mock recorder for MockProvider.
type MockProviderMockRecorder struct {
	mock *MockProvider
}

// NewMockProvider creates a new mock instance.
func NewMockProvider(ctrl *gomock.Controller) *MockProvider {
	mock := &MockProvider{ctrl: ctrl}
	mock.recorder = &MockProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProvider) EXPECT() *MockProviderMockRecorder {
	return m.recorder
}

// GetKVStore mocks base method.
func (m *MockProvider) GetKVStore(namespace, name string) (KVStore, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetKVStore", namespace, name)
	ret0, _ := ret[0].(KVStore)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetKVStore indicates an expected call of GetKVStore.
func (mr *MockProviderMockRecorder) GetKVStore(namespace, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetKVStore", reflect.TypeOf((*MockProvider)(nil).GetKVStore), namespace, name)
}

// MockKVStore is a mock of KVStore interface.
type MockKVStore struct {
	ctrl     *gomock.Controller
	recorder *MockKVStoreMockRecorder
}

// MockKVStoreMockRecorder is the mock recorder for MockKVStore.
type MockKVStoreMockRecorder struct {
	mock *MockKVStore
}

// NewMockKVStore creates a new mock instance.
func NewMockKVStore(ctrl *gomock.Controller) *MockKVStore {
	mock := &MockKVStore{ctrl: ctrl}
	mock.recorder = &MockKVStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKVStore) EXPECT() *MockKVStoreMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockKVStore) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockKVStoreMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockKVStore)(nil).Close))
}

// Read mocks base method.
func (m *MockKVStore) Read(fn func(ReadTx) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Read", fn)
	ret0, _ := ret[0].(error)
	return ret0
}

// Read indicates an expected call of Read.
func (mr *MockKVStoreMockRecorder) Read(fn interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Read", reflect.TypeOf((*MockKVStore)(nil).Read), fn)
}

// ReadBucket mocks base method.
func (m *MockKVStore) ReadBucket(bucketName string, fn func(BucketReader) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadBucket", bucketName, fn)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReadBucket indicates an expected call of ReadBucket.
func (mr *MockKVStoreMockRecorder) ReadBucket(bucketName, fn interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadBucket", reflect.TypeOf((*MockKVStore)(nil).ReadBucket), bucketName, fn)
}

// Write mocks base method.
func (m *MockKVStore) Write(fn func(WriteTx) error, opts ...TxOption) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{fn}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Write", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write.
func (mr *MockKVStoreMockRecorder) Write(fn interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{fn}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockKVStore)(nil).Write), varargs...)
}

// WriteBucket mocks base method.
func (m *MockKVStore) WriteBucket(bucketName string, fn func(BucketWriter) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteBucket", bucketName, fn)
	ret0, _ := ret[0].(error)
	return ret0
}

// WriteBucket indicates an expected call of WriteBucket.
func (mr *MockKVStoreMockRecorder) WriteBucket(bucketName, fn interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteBucket", reflect.TypeOf((*MockKVStore)(nil).WriteBucket), bucketName, fn)
}

// MockTxOption is a mock of TxOption interface.
type MockTxOption struct {
	ctrl     *gomock.Controller
	recorder *MockTxOptionMockRecorder
}

// MockTxOptionMockRecorder is the mock recorder for MockTxOption.
type MockTxOptionMockRecorder struct {
	mock *MockTxOption
}

// NewMockTxOption creates a new mock instance.
func NewMockTxOption(ctrl *gomock.Controller) *MockTxOption {
	mock := &MockTxOption{ctrl: ctrl}
	mock.recorder = &MockTxOptionMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTxOption) EXPECT() *MockTxOptionMockRecorder {
	return m.recorder
}

// MockWriteTx is a mock of WriteTx interface.
type MockWriteTx struct {
	ctrl     *gomock.Controller
	recorder *MockWriteTxMockRecorder
}

// MockWriteTxMockRecorder is the mock recorder for MockWriteTx.
type MockWriteTxMockRecorder struct {
	mock *MockWriteTx
}

// NewMockWriteTx creates a new mock instance.
func NewMockWriteTx(ctrl *gomock.Controller) *MockWriteTx {
	mock := &MockWriteTx{ctrl: ctrl}
	mock.recorder = &MockWriteTxMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWriteTx) EXPECT() *MockWriteTxMockRecorder {
	return m.recorder
}

// Bucket mocks base method.
func (m *MockWriteTx) Bucket(bucketName string) (BucketWriter, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Bucket", bucketName)
	ret0, _ := ret[0].(BucketWriter)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Bucket indicates an expected call of Bucket.
func (mr *MockWriteTxMockRecorder) Bucket(bucketName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Bucket", reflect.TypeOf((*MockWriteTx)(nil).Bucket), bucketName)
}

// MockReadTx is a mock of ReadTx interface.
type MockReadTx struct {
	ctrl     *gomock.Controller
	recorder *MockReadTxMockRecorder
}

// MockReadTxMockRecorder is the mock recorder for MockReadTx.
type MockReadTxMockRecorder struct {
	mock *MockReadTx
}

// NewMockReadTx creates a new mock instance.
func NewMockReadTx(ctrl *gomock.Controller) *MockReadTx {
	mock := &MockReadTx{ctrl: ctrl}
	mock.recorder = &MockReadTxMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReadTx) EXPECT() *MockReadTxMockRecorder {
	return m.recorder
}

// Bucket mocks base method.
func (m *MockReadTx) Bucket(bucketName string) (BucketReader, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Bucket", bucketName)
	ret0, _ := ret[0].(BucketReader)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Bucket indicates an expected call of Bucket.
func (mr *MockReadTxMockRecorder) Bucket(bucketName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Bucket", reflect.TypeOf((*MockReadTx)(nil).Bucket), bucketName)
}

// MockBucketReader is a mock of BucketReader interface.
type MockBucketReader struct {
	ctrl     *gomock.Controller
	recorder *MockBucketReaderMockRecorder
}

// MockBucketReaderMockRecorder is the mock recorder for MockBucketReader.
type MockBucketReaderMockRecorder struct {
	mock *MockBucketReader
}

// NewMockBucketReader creates a new mock instance.
func NewMockBucketReader(ctrl *gomock.Controller) *MockBucketReader {
	mock := &MockBucketReader{ctrl: ctrl}
	mock.recorder = &MockBucketReaderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBucketReader) EXPECT() *MockBucketReaderMockRecorder {
	return m.recorder
}

// Cursor mocks base method.
func (m *MockBucketReader) Cursor() (Cursor, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cursor")
	ret0, _ := ret[0].(Cursor)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Cursor indicates an expected call of Cursor.
func (mr *MockBucketReaderMockRecorder) Cursor() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cursor", reflect.TypeOf((*MockBucketReader)(nil).Cursor))
}

// Get mocks base method.
func (m *MockBucketReader) Get(key []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockBucketReaderMockRecorder) Get(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockBucketReader)(nil).Get), key)
}

// Stats mocks base method.
func (m *MockBucketReader) Stats() BucketStats {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stats")
	ret0, _ := ret[0].(BucketStats)
	return ret0
}

// Stats indicates an expected call of Stats.
func (mr *MockBucketReaderMockRecorder) Stats() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stats", reflect.TypeOf((*MockBucketReader)(nil).Stats))
}

// MockBucketWriter is a mock of BucketWriter interface.
type MockBucketWriter struct {
	ctrl     *gomock.Controller
	recorder *MockBucketWriterMockRecorder
}

// MockBucketWriterMockRecorder is the mock recorder for MockBucketWriter.
type MockBucketWriterMockRecorder struct {
	mock *MockBucketWriter
}

// NewMockBucketWriter creates a new mock instance.
func NewMockBucketWriter(ctrl *gomock.Controller) *MockBucketWriter {
	mock := &MockBucketWriter{ctrl: ctrl}
	mock.recorder = &MockBucketWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBucketWriter) EXPECT() *MockBucketWriterMockRecorder {
	return m.recorder
}

// Cursor mocks base method.
func (m *MockBucketWriter) Cursor() (Cursor, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cursor")
	ret0, _ := ret[0].(Cursor)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Cursor indicates an expected call of Cursor.
func (mr *MockBucketWriterMockRecorder) Cursor() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cursor", reflect.TypeOf((*MockBucketWriter)(nil).Cursor))
}

// Delete mocks base method.
func (m *MockBucketWriter) Delete(key []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", key)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockBucketWriterMockRecorder) Delete(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockBucketWriter)(nil).Delete), key)
}

// Get mocks base method.
func (m *MockBucketWriter) Get(key []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockBucketWriterMockRecorder) Get(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockBucketWriter)(nil).Get), key)
}

// Put mocks base method.
func (m *MockBucketWriter) Put(key, value []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Put", key, value)
	ret0, _ := ret[0].(error)
	return ret0
}

// Put indicates an expected call of Put.
func (mr *MockBucketWriterMockRecorder) Put(key, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockBucketWriter)(nil).Put), key, value)
}

// Stats mocks base method.
func (m *MockBucketWriter) Stats() BucketStats {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stats")
	ret0, _ := ret[0].(BucketStats)
	return ret0
}

// Stats indicates an expected call of Stats.
func (mr *MockBucketWriterMockRecorder) Stats() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stats", reflect.TypeOf((*MockBucketWriter)(nil).Stats))
}

// MockCursor is a mock of Cursor interface.
type MockCursor struct {
	ctrl     *gomock.Controller
	recorder *MockCursorMockRecorder
}

// MockCursorMockRecorder is the mock recorder for MockCursor.
type MockCursorMockRecorder struct {
	mock *MockCursor
}

// NewMockCursor creates a new mock instance.
func NewMockCursor(ctrl *gomock.Controller) *MockCursor {
	mock := &MockCursor{ctrl: ctrl}
	mock.recorder = &MockCursorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCursor) EXPECT() *MockCursorMockRecorder {
	return m.recorder
}

// Next mocks base method.
func (m *MockCursor) Next() ([]byte, []byte) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Next")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].([]byte)
	return ret0, ret1
}

// Next indicates an expected call of Next.
func (mr *MockCursorMockRecorder) Next() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Next", reflect.TypeOf((*MockCursor)(nil).Next))
}

// Seek mocks base method.
func (m *MockCursor) Seek(seek []byte) ([]byte, []byte) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Seek", seek)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].([]byte)
	return ret0, ret1
}

// Seek indicates an expected call of Seek.
func (mr *MockCursorMockRecorder) Seek(seek interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Seek", reflect.TypeOf((*MockCursor)(nil).Seek), seek)
}
