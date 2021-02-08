// Code generated by MockGen. DO NOT EDIT.
// Source: core/engine.go

// Package core is a generated GoMock package.
package core

import (
	gomock "github.com/golang/mock/gomock"
	v4 "github.com/labstack/echo/v4"
	reflect "reflect"
)

// MockRoutable is a mock of Routable interface
type MockRoutable struct {
	ctrl     *gomock.Controller
	recorder *MockRoutableMockRecorder
}

// MockRoutableMockRecorder is the mock recorder for MockRoutable
type MockRoutableMockRecorder struct {
	mock *MockRoutable
}

// NewMockRoutable creates a new mock instance
func NewMockRoutable(ctrl *gomock.Controller) *MockRoutable {
	mock := &MockRoutable{ctrl: ctrl}
	mock.recorder = &MockRoutableMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRoutable) EXPECT() *MockRoutableMockRecorder {
	return m.recorder
}

// Routes mocks base method
func (m *MockRoutable) Routes(router EchoRouter) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Routes", router)
}

// Routes indicates an expected call of Routes
func (mr *MockRoutableMockRecorder) Routes(router interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Routes", reflect.TypeOf((*MockRoutable)(nil).Routes), router)
}

// MockEchoServer is a mock of EchoServer interface
type MockEchoServer struct {
	ctrl     *gomock.Controller
	recorder *MockEchoServerMockRecorder
}

// MockEchoServerMockRecorder is the mock recorder for MockEchoServer
type MockEchoServerMockRecorder struct {
	mock *MockEchoServer
}

// NewMockEchoServer creates a new mock instance
func NewMockEchoServer(ctrl *gomock.Controller) *MockEchoServer {
	mock := &MockEchoServer{ctrl: ctrl}
	mock.recorder = &MockEchoServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockEchoServer) EXPECT() *MockEchoServerMockRecorder {
	return m.recorder
}

// CONNECT mocks base method
func (m_2 *MockEchoServer) CONNECT(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "CONNECT", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// CONNECT indicates an expected call of CONNECT
func (mr *MockEchoServerMockRecorder) CONNECT(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CONNECT", reflect.TypeOf((*MockEchoServer)(nil).CONNECT), varargs...)
}

// DELETE mocks base method
func (m_2 *MockEchoServer) DELETE(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "DELETE", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// DELETE indicates an expected call of DELETE
func (mr *MockEchoServerMockRecorder) DELETE(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DELETE", reflect.TypeOf((*MockEchoServer)(nil).DELETE), varargs...)
}

// GET mocks base method
func (m_2 *MockEchoServer) GET(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "GET", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// GET indicates an expected call of GET
func (mr *MockEchoServerMockRecorder) GET(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GET", reflect.TypeOf((*MockEchoServer)(nil).GET), varargs...)
}

// HEAD mocks base method
func (m_2 *MockEchoServer) HEAD(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "HEAD", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// HEAD indicates an expected call of HEAD
func (mr *MockEchoServerMockRecorder) HEAD(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HEAD", reflect.TypeOf((*MockEchoServer)(nil).HEAD), varargs...)
}

// OPTIONS mocks base method
func (m_2 *MockEchoServer) OPTIONS(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "OPTIONS", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// OPTIONS indicates an expected call of OPTIONS
func (mr *MockEchoServerMockRecorder) OPTIONS(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OPTIONS", reflect.TypeOf((*MockEchoServer)(nil).OPTIONS), varargs...)
}

// PATCH mocks base method
func (m_2 *MockEchoServer) PATCH(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "PATCH", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// PATCH indicates an expected call of PATCH
func (mr *MockEchoServerMockRecorder) PATCH(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PATCH", reflect.TypeOf((*MockEchoServer)(nil).PATCH), varargs...)
}

// POST mocks base method
func (m_2 *MockEchoServer) POST(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "POST", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// POST indicates an expected call of POST
func (mr *MockEchoServerMockRecorder) POST(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "POST", reflect.TypeOf((*MockEchoServer)(nil).POST), varargs...)
}

// PUT mocks base method
func (m_2 *MockEchoServer) PUT(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "PUT", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// PUT indicates an expected call of PUT
func (mr *MockEchoServerMockRecorder) PUT(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PUT", reflect.TypeOf((*MockEchoServer)(nil).PUT), varargs...)
}

// TRACE mocks base method
func (m_2 *MockEchoServer) TRACE(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "TRACE", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// TRACE indicates an expected call of TRACE
func (mr *MockEchoServerMockRecorder) TRACE(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TRACE", reflect.TypeOf((*MockEchoServer)(nil).TRACE), varargs...)
}

// Start mocks base method
func (m *MockEchoServer) Start(address string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start", address)
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start
func (mr *MockEchoServerMockRecorder) Start(address interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockEchoServer)(nil).Start), address)
}

// MockEchoRouter is a mock of EchoRouter interface
type MockEchoRouter struct {
	ctrl     *gomock.Controller
	recorder *MockEchoRouterMockRecorder
}

// MockEchoRouterMockRecorder is the mock recorder for MockEchoRouter
type MockEchoRouterMockRecorder struct {
	mock *MockEchoRouter
}

// NewMockEchoRouter creates a new mock instance
func NewMockEchoRouter(ctrl *gomock.Controller) *MockEchoRouter {
	mock := &MockEchoRouter{ctrl: ctrl}
	mock.recorder = &MockEchoRouterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockEchoRouter) EXPECT() *MockEchoRouterMockRecorder {
	return m.recorder
}

// CONNECT mocks base method
func (m_2 *MockEchoRouter) CONNECT(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "CONNECT", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// CONNECT indicates an expected call of CONNECT
func (mr *MockEchoRouterMockRecorder) CONNECT(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CONNECT", reflect.TypeOf((*MockEchoRouter)(nil).CONNECT), varargs...)
}

// DELETE mocks base method
func (m_2 *MockEchoRouter) DELETE(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "DELETE", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// DELETE indicates an expected call of DELETE
func (mr *MockEchoRouterMockRecorder) DELETE(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DELETE", reflect.TypeOf((*MockEchoRouter)(nil).DELETE), varargs...)
}

// GET mocks base method
func (m_2 *MockEchoRouter) GET(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "GET", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// GET indicates an expected call of GET
func (mr *MockEchoRouterMockRecorder) GET(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GET", reflect.TypeOf((*MockEchoRouter)(nil).GET), varargs...)
}

// HEAD mocks base method
func (m_2 *MockEchoRouter) HEAD(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "HEAD", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// HEAD indicates an expected call of HEAD
func (mr *MockEchoRouterMockRecorder) HEAD(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HEAD", reflect.TypeOf((*MockEchoRouter)(nil).HEAD), varargs...)
}

// OPTIONS mocks base method
func (m_2 *MockEchoRouter) OPTIONS(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "OPTIONS", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// OPTIONS indicates an expected call of OPTIONS
func (mr *MockEchoRouterMockRecorder) OPTIONS(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OPTIONS", reflect.TypeOf((*MockEchoRouter)(nil).OPTIONS), varargs...)
}

// PATCH mocks base method
func (m_2 *MockEchoRouter) PATCH(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "PATCH", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// PATCH indicates an expected call of PATCH
func (mr *MockEchoRouterMockRecorder) PATCH(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PATCH", reflect.TypeOf((*MockEchoRouter)(nil).PATCH), varargs...)
}

// POST mocks base method
func (m_2 *MockEchoRouter) POST(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "POST", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// POST indicates an expected call of POST
func (mr *MockEchoRouterMockRecorder) POST(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "POST", reflect.TypeOf((*MockEchoRouter)(nil).POST), varargs...)
}

// PUT mocks base method
func (m_2 *MockEchoRouter) PUT(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "PUT", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// PUT indicates an expected call of PUT
func (mr *MockEchoRouterMockRecorder) PUT(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PUT", reflect.TypeOf((*MockEchoRouter)(nil).PUT), varargs...)
}

// TRACE mocks base method
func (m_2 *MockEchoRouter) TRACE(path string, h v4.HandlerFunc, m ...v4.MiddlewareFunc) *v4.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "TRACE", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// TRACE indicates an expected call of TRACE
func (mr *MockEchoRouterMockRecorder) TRACE(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TRACE", reflect.TypeOf((*MockEchoRouter)(nil).TRACE), varargs...)
}

// MockRunnable is a mock of Runnable interface
type MockRunnable struct {
	ctrl     *gomock.Controller
	recorder *MockRunnableMockRecorder
}

// MockRunnableMockRecorder is the mock recorder for MockRunnable
type MockRunnableMockRecorder struct {
	mock *MockRunnable
}

// NewMockRunnable creates a new mock instance
func NewMockRunnable(ctrl *gomock.Controller) *MockRunnable {
	mock := &MockRunnable{ctrl: ctrl}
	mock.recorder = &MockRunnableMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRunnable) EXPECT() *MockRunnableMockRecorder {
	return m.recorder
}

// Start mocks base method
func (m *MockRunnable) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start
func (mr *MockRunnableMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockRunnable)(nil).Start))
}

// Shutdown mocks base method
func (m *MockRunnable) Shutdown() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Shutdown")
	ret0, _ := ret[0].(error)
	return ret0
}

// Shutdown indicates an expected call of Shutdown
func (mr *MockRunnableMockRecorder) Shutdown() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Shutdown", reflect.TypeOf((*MockRunnable)(nil).Shutdown))
}

// MockConfigurable is a mock of Configurable interface
type MockConfigurable struct {
	ctrl     *gomock.Controller
	recorder *MockConfigurableMockRecorder
}

// MockConfigurableMockRecorder is the mock recorder for MockConfigurable
type MockConfigurableMockRecorder struct {
	mock *MockConfigurable
}

// NewMockConfigurable creates a new mock instance
func NewMockConfigurable(ctrl *gomock.Controller) *MockConfigurable {
	mock := &MockConfigurable{ctrl: ctrl}
	mock.recorder = &MockConfigurableMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockConfigurable) EXPECT() *MockConfigurableMockRecorder {
	return m.recorder
}

// Configure mocks base method
func (m *MockConfigurable) Configure(config ServerConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Configure", config)
	ret0, _ := ret[0].(error)
	return ret0
}

// Configure indicates an expected call of Configure
func (mr *MockConfigurableMockRecorder) Configure(config interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Configure", reflect.TypeOf((*MockConfigurable)(nil).Configure), config)
}

// MockViewableDiagnostics is a mock of ViewableDiagnostics interface
type MockViewableDiagnostics struct {
	ctrl     *gomock.Controller
	recorder *MockViewableDiagnosticsMockRecorder
}

// MockViewableDiagnosticsMockRecorder is the mock recorder for MockViewableDiagnostics
type MockViewableDiagnosticsMockRecorder struct {
	mock *MockViewableDiagnostics
}

// NewMockViewableDiagnostics creates a new mock instance
func NewMockViewableDiagnostics(ctrl *gomock.Controller) *MockViewableDiagnostics {
	mock := &MockViewableDiagnostics{ctrl: ctrl}
	mock.recorder = &MockViewableDiagnosticsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockViewableDiagnostics) EXPECT() *MockViewableDiagnosticsMockRecorder {
	return m.recorder
}

// Name mocks base method
func (m *MockViewableDiagnostics) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name
func (mr *MockViewableDiagnosticsMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockViewableDiagnostics)(nil).Name))
}

// Diagnostics mocks base method
func (m *MockViewableDiagnostics) Diagnostics() []DiagnosticResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Diagnostics")
	ret0, _ := ret[0].([]DiagnosticResult)
	return ret0
}

// Diagnostics indicates an expected call of Diagnostics
func (mr *MockViewableDiagnosticsMockRecorder) Diagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Diagnostics", reflect.TypeOf((*MockViewableDiagnostics)(nil).Diagnostics))
}

// MockDiagnosable is a mock of Diagnosable interface
type MockDiagnosable struct {
	ctrl     *gomock.Controller
	recorder *MockDiagnosableMockRecorder
}

// MockDiagnosableMockRecorder is the mock recorder for MockDiagnosable
type MockDiagnosableMockRecorder struct {
	mock *MockDiagnosable
}

// NewMockDiagnosable creates a new mock instance
func NewMockDiagnosable(ctrl *gomock.Controller) *MockDiagnosable {
	mock := &MockDiagnosable{ctrl: ctrl}
	mock.recorder = &MockDiagnosableMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockDiagnosable) EXPECT() *MockDiagnosableMockRecorder {
	return m.recorder
}

// Diagnostics mocks base method
func (m *MockDiagnosable) Diagnostics() []DiagnosticResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Diagnostics")
	ret0, _ := ret[0].([]DiagnosticResult)
	return ret0
}

// Diagnostics indicates an expected call of Diagnostics
func (mr *MockDiagnosableMockRecorder) Diagnostics() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Diagnostics", reflect.TypeOf((*MockDiagnosable)(nil).Diagnostics))
}

// MockEngine is a mock of Engine interface
type MockEngine struct {
	ctrl     *gomock.Controller
	recorder *MockEngineMockRecorder
}

// MockEngineMockRecorder is the mock recorder for MockEngine
type MockEngineMockRecorder struct {
	mock *MockEngine
}

// NewMockEngine creates a new mock instance
func NewMockEngine(ctrl *gomock.Controller) *MockEngine {
	mock := &MockEngine{ctrl: ctrl}
	mock.recorder = &MockEngineMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockEngine) EXPECT() *MockEngineMockRecorder {
	return m.recorder
}

// MockNamed is a mock of Named interface
type MockNamed struct {
	ctrl     *gomock.Controller
	recorder *MockNamedMockRecorder
}

// MockNamedMockRecorder is the mock recorder for MockNamed
type MockNamedMockRecorder struct {
	mock *MockNamed
}

// NewMockNamed creates a new mock instance
func NewMockNamed(ctrl *gomock.Controller) *MockNamed {
	mock := &MockNamed{ctrl: ctrl}
	mock.recorder = &MockNamedMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNamed) EXPECT() *MockNamedMockRecorder {
	return m.recorder
}

// Name mocks base method
func (m *MockNamed) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name
func (mr *MockNamedMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockNamed)(nil).Name))
}

// MockInjectable is a mock of Injectable interface
type MockInjectable struct {
	ctrl     *gomock.Controller
	recorder *MockInjectableMockRecorder
}

// MockInjectableMockRecorder is the mock recorder for MockInjectable
type MockInjectableMockRecorder struct {
	mock *MockInjectable
}

// NewMockInjectable creates a new mock instance
func NewMockInjectable(ctrl *gomock.Controller) *MockInjectable {
	mock := &MockInjectable{ctrl: ctrl}
	mock.recorder = &MockInjectableMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockInjectable) EXPECT() *MockInjectableMockRecorder {
	return m.recorder
}

// Name mocks base method
func (m *MockInjectable) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name
func (mr *MockInjectableMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockInjectable)(nil).Name))
}

// ConfigKey mocks base method
func (m *MockInjectable) ConfigKey() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfigKey")
	ret0, _ := ret[0].(string)
	return ret0
}

// ConfigKey indicates an expected call of ConfigKey
func (mr *MockInjectableMockRecorder) ConfigKey() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigKey", reflect.TypeOf((*MockInjectable)(nil).ConfigKey))
}

// Config mocks base method
func (m *MockInjectable) Config() interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Config")
	ret0, _ := ret[0].(interface{})
	return ret0
}

// Config indicates an expected call of Config
func (mr *MockInjectableMockRecorder) Config() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Config", reflect.TypeOf((*MockInjectable)(nil).Config))
}
