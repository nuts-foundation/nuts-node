// Code generated by MockGen. DO NOT EDIT.
// Source: core/echo.go

// Package core is a generated GoMock package.
package core

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	echo "github.com/labstack/echo/v4"
)

// MockEchoServer is a mock of EchoServer interface.
type MockEchoServer struct {
	ctrl     *gomock.Controller
	recorder *MockEchoServerMockRecorder
}

// MockEchoServerMockRecorder is the mock recorder for MockEchoServer.
type MockEchoServerMockRecorder struct {
	mock *MockEchoServer
}

// NewMockEchoServer creates a new mock instance.
func NewMockEchoServer(ctrl *gomock.Controller) *MockEchoServer {
	mock := &MockEchoServer{ctrl: ctrl}
	mock.recorder = &MockEchoServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEchoServer) EXPECT() *MockEchoServerMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockEchoServer) Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{method, path, handler}
	for _, a := range middleware {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Add", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockEchoServerMockRecorder) Add(method, path, handler interface{}, middleware ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{method, path, handler}, middleware...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockEchoServer)(nil).Add), varargs...)
}

// CONNECT mocks base method.
func (m_2 *MockEchoServer) CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "CONNECT", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// CONNECT indicates an expected call of CONNECT.
func (mr *MockEchoServerMockRecorder) CONNECT(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CONNECT", reflect.TypeOf((*MockEchoServer)(nil).CONNECT), varargs...)
}

// DELETE mocks base method.
func (m_2 *MockEchoServer) DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "DELETE", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// DELETE indicates an expected call of DELETE.
func (mr *MockEchoServerMockRecorder) DELETE(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DELETE", reflect.TypeOf((*MockEchoServer)(nil).DELETE), varargs...)
}

// GET mocks base method.
func (m_2 *MockEchoServer) GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "GET", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// GET indicates an expected call of GET.
func (mr *MockEchoServerMockRecorder) GET(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GET", reflect.TypeOf((*MockEchoServer)(nil).GET), varargs...)
}

// HEAD mocks base method.
func (m_2 *MockEchoServer) HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "HEAD", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// HEAD indicates an expected call of HEAD.
func (mr *MockEchoServerMockRecorder) HEAD(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HEAD", reflect.TypeOf((*MockEchoServer)(nil).HEAD), varargs...)
}

// OPTIONS mocks base method.
func (m_2 *MockEchoServer) OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "OPTIONS", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// OPTIONS indicates an expected call of OPTIONS.
func (mr *MockEchoServerMockRecorder) OPTIONS(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OPTIONS", reflect.TypeOf((*MockEchoServer)(nil).OPTIONS), varargs...)
}

// PATCH mocks base method.
func (m_2 *MockEchoServer) PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "PATCH", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// PATCH indicates an expected call of PATCH.
func (mr *MockEchoServerMockRecorder) PATCH(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PATCH", reflect.TypeOf((*MockEchoServer)(nil).PATCH), varargs...)
}

// POST mocks base method.
func (m_2 *MockEchoServer) POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "POST", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// POST indicates an expected call of POST.
func (mr *MockEchoServerMockRecorder) POST(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "POST", reflect.TypeOf((*MockEchoServer)(nil).POST), varargs...)
}

// PUT mocks base method.
func (m_2 *MockEchoServer) PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "PUT", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// PUT indicates an expected call of PUT.
func (mr *MockEchoServerMockRecorder) PUT(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PUT", reflect.TypeOf((*MockEchoServer)(nil).PUT), varargs...)
}

// Shutdown mocks base method.
func (m *MockEchoServer) Shutdown(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Shutdown", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Shutdown indicates an expected call of Shutdown.
func (mr *MockEchoServerMockRecorder) Shutdown(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Shutdown", reflect.TypeOf((*MockEchoServer)(nil).Shutdown), ctx)
}

// Start mocks base method.
func (m *MockEchoServer) Start(address string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start", address)
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockEchoServerMockRecorder) Start(address interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockEchoServer)(nil).Start), address)
}

// TRACE mocks base method.
func (m_2 *MockEchoServer) TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "TRACE", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// TRACE indicates an expected call of TRACE.
func (mr *MockEchoServerMockRecorder) TRACE(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TRACE", reflect.TypeOf((*MockEchoServer)(nil).TRACE), varargs...)
}

// MockEchoRouter is a mock of EchoRouter interface.
type MockEchoRouter struct {
	ctrl     *gomock.Controller
	recorder *MockEchoRouterMockRecorder
}

// MockEchoRouterMockRecorder is the mock recorder for MockEchoRouter.
type MockEchoRouterMockRecorder struct {
	mock *MockEchoRouter
}

// NewMockEchoRouter creates a new mock instance.
func NewMockEchoRouter(ctrl *gomock.Controller) *MockEchoRouter {
	mock := &MockEchoRouter{ctrl: ctrl}
	mock.recorder = &MockEchoRouterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEchoRouter) EXPECT() *MockEchoRouterMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockEchoRouter) Add(method, path string, handler echo.HandlerFunc, middleware ...echo.MiddlewareFunc) *echo.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{method, path, handler}
	for _, a := range middleware {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Add", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockEchoRouterMockRecorder) Add(method, path, handler interface{}, middleware ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{method, path, handler}, middleware...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockEchoRouter)(nil).Add), varargs...)
}

// CONNECT mocks base method.
func (m_2 *MockEchoRouter) CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "CONNECT", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// CONNECT indicates an expected call of CONNECT.
func (mr *MockEchoRouterMockRecorder) CONNECT(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CONNECT", reflect.TypeOf((*MockEchoRouter)(nil).CONNECT), varargs...)
}

// DELETE mocks base method.
func (m_2 *MockEchoRouter) DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "DELETE", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// DELETE indicates an expected call of DELETE.
func (mr *MockEchoRouterMockRecorder) DELETE(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DELETE", reflect.TypeOf((*MockEchoRouter)(nil).DELETE), varargs...)
}

// GET mocks base method.
func (m_2 *MockEchoRouter) GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "GET", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// GET indicates an expected call of GET.
func (mr *MockEchoRouterMockRecorder) GET(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GET", reflect.TypeOf((*MockEchoRouter)(nil).GET), varargs...)
}

// HEAD mocks base method.
func (m_2 *MockEchoRouter) HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "HEAD", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// HEAD indicates an expected call of HEAD.
func (mr *MockEchoRouterMockRecorder) HEAD(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HEAD", reflect.TypeOf((*MockEchoRouter)(nil).HEAD), varargs...)
}

// OPTIONS mocks base method.
func (m_2 *MockEchoRouter) OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "OPTIONS", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// OPTIONS indicates an expected call of OPTIONS.
func (mr *MockEchoRouterMockRecorder) OPTIONS(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OPTIONS", reflect.TypeOf((*MockEchoRouter)(nil).OPTIONS), varargs...)
}

// PATCH mocks base method.
func (m_2 *MockEchoRouter) PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "PATCH", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// PATCH indicates an expected call of PATCH.
func (mr *MockEchoRouterMockRecorder) PATCH(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PATCH", reflect.TypeOf((*MockEchoRouter)(nil).PATCH), varargs...)
}

// POST mocks base method.
func (m_2 *MockEchoRouter) POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "POST", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// POST indicates an expected call of POST.
func (mr *MockEchoRouterMockRecorder) POST(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "POST", reflect.TypeOf((*MockEchoRouter)(nil).POST), varargs...)
}

// PUT mocks base method.
func (m_2 *MockEchoRouter) PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "PUT", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// PUT indicates an expected call of PUT.
func (mr *MockEchoRouterMockRecorder) PUT(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PUT", reflect.TypeOf((*MockEchoRouter)(nil).PUT), varargs...)
}

// TRACE mocks base method.
func (m_2 *MockEchoRouter) TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	m_2.ctrl.T.Helper()
	varargs := []interface{}{path, h}
	for _, a := range m {
		varargs = append(varargs, a)
	}
	ret := m_2.ctrl.Call(m_2, "TRACE", varargs...)
	ret0, _ := ret[0].(*echo.Route)
	return ret0
}

// TRACE indicates an expected call of TRACE.
func (mr *MockEchoRouterMockRecorder) TRACE(path, h interface{}, m ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{path, h}, m...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TRACE", reflect.TypeOf((*MockEchoRouter)(nil).TRACE), varargs...)
}
