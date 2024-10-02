//
// Copyright (C) 2021. Nuts community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.27.3
// source: transport/grpc/testprotocol.proto

package grpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Test_DoStuff_FullMethodName = "/grpc.Test/DoStuff"
)

// TestClient is the client API for Test service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TestClient interface {
	DoStuff(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[TestMessage, TestMessage], error)
}

type testClient struct {
	cc grpc.ClientConnInterface
}

func NewTestClient(cc grpc.ClientConnInterface) TestClient {
	return &testClient{cc}
}

func (c *testClient) DoStuff(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[TestMessage, TestMessage], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Test_ServiceDesc.Streams[0], Test_DoStuff_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[TestMessage, TestMessage]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Test_DoStuffClient = grpc.BidiStreamingClient[TestMessage, TestMessage]

// TestServer is the server API for Test service.
// All implementations should embed UnimplementedTestServer
// for forward compatibility.
type TestServer interface {
	DoStuff(grpc.BidiStreamingServer[TestMessage, TestMessage]) error
}

// UnimplementedTestServer should be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedTestServer struct{}

func (UnimplementedTestServer) DoStuff(grpc.BidiStreamingServer[TestMessage, TestMessage]) error {
	return status.Errorf(codes.Unimplemented, "method DoStuff not implemented")
}
func (UnimplementedTestServer) testEmbeddedByValue() {}

// UnsafeTestServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TestServer will
// result in compilation errors.
type UnsafeTestServer interface {
	mustEmbedUnimplementedTestServer()
}

func RegisterTestServer(s grpc.ServiceRegistrar, srv TestServer) {
	// If the following call pancis, it indicates UnimplementedTestServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Test_ServiceDesc, srv)
}

func _Test_DoStuff_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TestServer).DoStuff(&grpc.GenericServerStream[TestMessage, TestMessage]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Test_DoStuffServer = grpc.BidiStreamingServer[TestMessage, TestMessage]

// Test_ServiceDesc is the grpc.ServiceDesc for Test service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Test_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.Test",
	HandlerType: (*TestServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "DoStuff",
			Handler:       _Test_DoStuff_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "transport/grpc/testprotocol.proto",
}
