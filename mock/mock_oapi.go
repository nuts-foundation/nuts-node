// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/deepmap/oapi-codegen/pkg/runtime (interfaces: EchoRouter)

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v4 "github.com/labstack/echo/v4"
)

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
func (m *MockEchoRouter) CONNECT(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CONNECT", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// CONNECT indicates an expected call of CONNECT
func (mr *MockEchoRouterMockRecorder) CONNECT(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CONNECT", reflect.TypeOf((*MockEchoRouter)(nil).CONNECT), varargs...)
}

// DELETE mocks base method
func (m *MockEchoRouter) DELETE(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DELETE", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// DELETE indicates an expected call of DELETE
func (mr *MockEchoRouterMockRecorder) DELETE(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DELETE", reflect.TypeOf((*MockEchoRouter)(nil).DELETE), varargs...)
}

// GET mocks base method
func (m *MockEchoRouter) GET(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GET", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// GET indicates an expected call of GET
func (mr *MockEchoRouterMockRecorder) GET(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GET", reflect.TypeOf((*MockEchoRouter)(nil).GET), varargs...)
}

// HEAD mocks base method
func (m *MockEchoRouter) HEAD(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "HEAD", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// HEAD indicates an expected call of HEAD
func (mr *MockEchoRouterMockRecorder) HEAD(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HEAD", reflect.TypeOf((*MockEchoRouter)(nil).HEAD), varargs...)
}

// OPTIONS mocks base method
func (m *MockEchoRouter) OPTIONS(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "OPTIONS", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// OPTIONS indicates an expected call of OPTIONS
func (mr *MockEchoRouterMockRecorder) OPTIONS(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OPTIONS", reflect.TypeOf((*MockEchoRouter)(nil).OPTIONS), varargs...)
}

// PATCH mocks base method
func (m *MockEchoRouter) PATCH(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "PATCH", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// PATCH indicates an expected call of PATCH
func (mr *MockEchoRouterMockRecorder) PATCH(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PATCH", reflect.TypeOf((*MockEchoRouter)(nil).PATCH), varargs...)
}

// POST mocks base method
func (m *MockEchoRouter) POST(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "POST", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// POST indicates an expected call of POST
func (mr *MockEchoRouterMockRecorder) POST(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "POST", reflect.TypeOf((*MockEchoRouter)(nil).POST), varargs...)
}

// PUT mocks base method
func (m *MockEchoRouter) PUT(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "PUT", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// PUT indicates an expected call of PUT
func (mr *MockEchoRouterMockRecorder) PUT(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PUT", reflect.TypeOf((*MockEchoRouter)(nil).PUT), varargs...)
}

// TRACE mocks base method
func (m *MockEchoRouter) TRACE(arg0 string, arg1 v4.HandlerFunc, arg2 ...v4.MiddlewareFunc) *v4.Route {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "TRACE", varargs...)
	ret0, _ := ret[0].(*v4.Route)
	return ret0
}

// TRACE indicates an expected call of TRACE
func (mr *MockEchoRouterMockRecorder) TRACE(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TRACE", reflect.TypeOf((*MockEchoRouter)(nil).TRACE), varargs...)
}
