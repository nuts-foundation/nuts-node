// Code generated by MockGen. DO NOT EDIT.
// Source: network/transport/grpc/interface.go

// Package grpc is a generated GoMock package.
package grpc

import (
	context "context"
	reflect "reflect"

	core "github.com/nuts-foundation/nuts-node/core"
	transport "github.com/nuts-foundation/nuts-node/network/transport"
	gomock "go.uber.org/mock/gomock"
	grpc "google.golang.org/grpc"
	metadata "google.golang.org/grpc/metadata"
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
func (m *MockProtocol) Configure(peerID transport.PeerID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure", peerID)
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure.
func (mr *MockProtocolMockRecorder) Configure(peerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockProtocol)(nil).Configure), peerID)
}

// CreateClientStream mocks base method.
func (m *MockProtocol) CreateClientStream(outgoingContext context.Context, grpcConn grpc.ClientConnInterface) (grpc.ClientStream, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateClientStream", outgoingContext, grpcConn)
	ret0, _ := ret[0].(grpc.ClientStream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateClientStream indicates an expected call of CreateClientStream.
func (mr *MockProtocolMockRecorder) CreateClientStream(outgoingContext, grpcConn interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateClientStream", reflect.TypeOf((*MockProtocol)(nil).CreateClientStream), outgoingContext, grpcConn)
}

// CreateEnvelope mocks base method.
func (m *MockProtocol) CreateEnvelope() interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateEnvelope")
	ret0, _ := ret[0].(interface{})
	return ret0
}

// CreateEnvelope indicates an expected call of CreateEnvelope.
func (mr *MockProtocolMockRecorder) CreateEnvelope() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateEnvelope", reflect.TypeOf((*MockProtocol)(nil).CreateEnvelope))
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

// GetMessageType mocks base method.
func (m *MockProtocol) GetMessageType(envelope interface{}) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMessageType", envelope)
	ret0, _ := ret[0].(string)
	return ret0
}

// GetMessageType indicates an expected call of GetMessageType.
func (mr *MockProtocolMockRecorder) GetMessageType(envelope interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMessageType", reflect.TypeOf((*MockProtocol)(nil).GetMessageType), envelope)
}

// Handle mocks base method.
func (m *MockProtocol) Handle(connection Connection, envelope interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Handle", connection, envelope)
	ret0, _ := ret[0].(error)
	return ret0
}

// Handle indicates an expected call of Handle.
func (mr *MockProtocolMockRecorder) Handle(connection, envelope interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Handle", reflect.TypeOf((*MockProtocol)(nil).Handle), connection, envelope)
}

// MethodName mocks base method.
func (m *MockProtocol) MethodName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MethodName")
	ret0, _ := ret[0].(string)
	return ret0
}

// MethodName indicates an expected call of MethodName.
func (mr *MockProtocolMockRecorder) MethodName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MethodName", reflect.TypeOf((*MockProtocol)(nil).MethodName))
}

// PeerDiagnostics mocks base method.
func (m *MockProtocol) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PeerDiagnostics")
	ret0, _ := ret[0].(map[transport.PeerID]transport.Diagnostics)
	return ret0
}

// PeerDiagnostics indicates an expected call of PeerDiagnostics.
func (mr *MockProtocolMockRecorder) PeerDiagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PeerDiagnostics", reflect.TypeOf((*MockProtocol)(nil).PeerDiagnostics))
}

// Register mocks base method.
func (m *MockProtocol) Register(registrar grpc.ServiceRegistrar, acceptor func(grpc.ServerStream) error, connectionList ConnectionList, connectionManager transport.ConnectionManager) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Register", registrar, acceptor, connectionList, connectionManager)
}

// Register indicates an expected call of Register.
func (mr *MockProtocolMockRecorder) Register(registrar, acceptor, connectionList, connectionManager interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockProtocol)(nil).Register), registrar, acceptor, connectionList, connectionManager)
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
func (m *MockProtocol) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop.
func (mr *MockProtocolMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockProtocol)(nil).Stop))
}

// UnwrapMessage mocks base method.
func (m *MockProtocol) UnwrapMessage(envelope interface{}) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnwrapMessage", envelope)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// UnwrapMessage indicates an expected call of UnwrapMessage.
func (mr *MockProtocolMockRecorder) UnwrapMessage(envelope interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnwrapMessage", reflect.TypeOf((*MockProtocol)(nil).UnwrapMessage), envelope)
}

// Version mocks base method.
func (m *MockProtocol) Version() int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Version")
	ret0, _ := ret[0].(int)
	return ret0
}

// Version indicates an expected call of Version.
func (mr *MockProtocolMockRecorder) Version() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Version", reflect.TypeOf((*MockProtocol)(nil).Version))
}

// MockStream is a mock of Stream interface.
type MockStream struct {
	ctrl     *gomock.Controller
	recorder *MockStreamMockRecorder
}

// MockStreamMockRecorder is the mock recorder for MockStream.
type MockStreamMockRecorder struct {
	mock *MockStream
}

// NewMockStream creates a new mock instance.
func NewMockStream(ctrl *gomock.Controller) *MockStream {
	mock := &MockStream{ctrl: ctrl}
	mock.recorder = &MockStreamMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStream) EXPECT() *MockStreamMockRecorder {
	return m.recorder
}

// Context mocks base method.
func (m *MockStream) Context() context.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockStreamMockRecorder) Context() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockStream)(nil).Context))
}

// RecvMsg mocks base method.
func (m_2 *MockStream) RecvMsg(m interface{}) error {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "RecvMsg", m)
	ret0, _ := ret[0].(error)
	return ret0
}

// RecvMsg indicates an expected call of RecvMsg.
func (mr *MockStreamMockRecorder) RecvMsg(m interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecvMsg", reflect.TypeOf((*MockStream)(nil).RecvMsg), m)
}

// SendMsg mocks base method.
func (m_2 *MockStream) SendMsg(m interface{}) error {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "SendMsg", m)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMsg indicates an expected call of SendMsg.
func (mr *MockStreamMockRecorder) SendMsg(m interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMsg", reflect.TypeOf((*MockStream)(nil).SendMsg), m)
}

// MockConn is a mock of Conn interface.
type MockConn struct {
	ctrl     *gomock.Controller
	recorder *MockConnMockRecorder
}

// MockConnMockRecorder is the mock recorder for MockConn.
type MockConnMockRecorder struct {
	mock *MockConn
}

// NewMockConn creates a new mock instance.
func NewMockConn(ctrl *gomock.Controller) *MockConn {
	mock := &MockConn{ctrl: ctrl}
	mock.recorder = &MockConnMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConn) EXPECT() *MockConnMockRecorder {
	return m.recorder
}

// Invoke mocks base method.
func (m *MockConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...grpc.CallOption) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, method, args, reply}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Invoke", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Invoke indicates an expected call of Invoke.
func (mr *MockConnMockRecorder) Invoke(ctx, method, args, reply interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, method, args, reply}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Invoke", reflect.TypeOf((*MockConn)(nil).Invoke), varargs...)
}

// NewStream mocks base method.
func (m *MockConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, desc, method}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "NewStream", varargs...)
	ret0, _ := ret[0].(grpc.ClientStream)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewStream indicates an expected call of NewStream.
func (mr *MockConnMockRecorder) NewStream(ctx, desc, method interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, desc, method}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewStream", reflect.TypeOf((*MockConn)(nil).NewStream), varargs...)
}

// MockClientStream is a mock of ClientStream interface.
type MockClientStream struct {
	ctrl     *gomock.Controller
	recorder *MockClientStreamMockRecorder
}

// MockClientStreamMockRecorder is the mock recorder for MockClientStream.
type MockClientStreamMockRecorder struct {
	mock *MockClientStream
}

// NewMockClientStream creates a new mock instance.
func NewMockClientStream(ctrl *gomock.Controller) *MockClientStream {
	mock := &MockClientStream{ctrl: ctrl}
	mock.recorder = &MockClientStreamMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientStream) EXPECT() *MockClientStreamMockRecorder {
	return m.recorder
}

// CloseSend mocks base method.
func (m *MockClientStream) CloseSend() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseSend")
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseSend indicates an expected call of CloseSend.
func (mr *MockClientStreamMockRecorder) CloseSend() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseSend", reflect.TypeOf((*MockClientStream)(nil).CloseSend))
}

// Context mocks base method.
func (m *MockClientStream) Context() context.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockClientStreamMockRecorder) Context() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockClientStream)(nil).Context))
}

// Header mocks base method.
func (m *MockClientStream) Header() (metadata.MD, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Header")
	ret0, _ := ret[0].(metadata.MD)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Header indicates an expected call of Header.
func (mr *MockClientStreamMockRecorder) Header() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Header", reflect.TypeOf((*MockClientStream)(nil).Header))
}

// RecvMsg mocks base method.
func (m_2 *MockClientStream) RecvMsg(m interface{}) error {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "RecvMsg", m)
	ret0, _ := ret[0].(error)
	return ret0
}

// RecvMsg indicates an expected call of RecvMsg.
func (mr *MockClientStreamMockRecorder) RecvMsg(m interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecvMsg", reflect.TypeOf((*MockClientStream)(nil).RecvMsg), m)
}

// SendMsg mocks base method.
func (m_2 *MockClientStream) SendMsg(m interface{}) error {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "SendMsg", m)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMsg indicates an expected call of SendMsg.
func (mr *MockClientStreamMockRecorder) SendMsg(m interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMsg", reflect.TypeOf((*MockClientStream)(nil).SendMsg), m)
}

// Trailer mocks base method.
func (m *MockClientStream) Trailer() metadata.MD {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trailer")
	ret0, _ := ret[0].(metadata.MD)
	return ret0
}

// Trailer indicates an expected call of Trailer.
func (mr *MockClientStreamMockRecorder) Trailer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trailer", reflect.TypeOf((*MockClientStream)(nil).Trailer))
}
