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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: transport/network.proto

package transport

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// We multiplex all of our messages over a single super-message type, because we're using streams. If we did not do that,
// we'd need to open a stream per operation, which would make the number of required streams explode (since we're
// building a full mesh network).
type NetworkMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Below are the messages that can be sent/received using the NetworkMessage. A NetworkMessage MAY contain multiple
	// messages.
	//
	// Types that are assignable to Message:
	//	*NetworkMessage_AdvertHashes
	//	*NetworkMessage_TransactionListQuery
	//	*NetworkMessage_TransactionList
	//	*NetworkMessage_TransactionPayloadQuery
	//	*NetworkMessage_TransactionPayload
	Message isNetworkMessage_Message `protobuf_oneof:"message"`
}

func (x *NetworkMessage) Reset() {
	*x = NetworkMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NetworkMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NetworkMessage) ProtoMessage() {}

func (x *NetworkMessage) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NetworkMessage.ProtoReflect.Descriptor instead.
func (*NetworkMessage) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{0}
}

func (m *NetworkMessage) GetMessage() isNetworkMessage_Message {
	if m != nil {
		return m.Message
	}
	return nil
}

func (x *NetworkMessage) GetAdvertHashes() *AdvertHashes {
	if x, ok := x.GetMessage().(*NetworkMessage_AdvertHashes); ok {
		return x.AdvertHashes
	}
	return nil
}

func (x *NetworkMessage) GetTransactionListQuery() *TransactionListQuery {
	if x, ok := x.GetMessage().(*NetworkMessage_TransactionListQuery); ok {
		return x.TransactionListQuery
	}
	return nil
}

func (x *NetworkMessage) GetTransactionList() *TransactionList {
	if x, ok := x.GetMessage().(*NetworkMessage_TransactionList); ok {
		return x.TransactionList
	}
	return nil
}

func (x *NetworkMessage) GetTransactionPayloadQuery() *TransactionPayloadQuery {
	if x, ok := x.GetMessage().(*NetworkMessage_TransactionPayloadQuery); ok {
		return x.TransactionPayloadQuery
	}
	return nil
}

func (x *NetworkMessage) GetTransactionPayload() *TransactionPayload {
	if x, ok := x.GetMessage().(*NetworkMessage_TransactionPayload); ok {
		return x.TransactionPayload
	}
	return nil
}

type isNetworkMessage_Message interface {
	isNetworkMessage_Message()
}

type NetworkMessage_AdvertHashes struct {
	AdvertHashes *AdvertHashes `protobuf:"bytes,100,opt,name=advertHashes,proto3,oneof"`
}

type NetworkMessage_TransactionListQuery struct {
	TransactionListQuery *TransactionListQuery `protobuf:"bytes,101,opt,name=TransactionListQuery,proto3,oneof"`
}

type NetworkMessage_TransactionList struct {
	TransactionList *TransactionList `protobuf:"bytes,102,opt,name=TransactionList,proto3,oneof"`
}

type NetworkMessage_TransactionPayloadQuery struct {
	TransactionPayloadQuery *TransactionPayloadQuery `protobuf:"bytes,103,opt,name=transactionPayloadQuery,proto3,oneof"`
}

type NetworkMessage_TransactionPayload struct {
	TransactionPayload *TransactionPayload `protobuf:"bytes,104,opt,name=transactionPayload,proto3,oneof"`
}

func (*NetworkMessage_AdvertHashes) isNetworkMessage_Message() {}

func (*NetworkMessage_TransactionListQuery) isNetworkMessage_Message() {}

func (*NetworkMessage_TransactionList) isNetworkMessage_Message() {}

func (*NetworkMessage_TransactionPayloadQuery) isNetworkMessage_Message() {}

func (*NetworkMessage_TransactionPayload) isNetworkMessage_Message() {}

// Headers contains protocol metadata.
type Header struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// version contains the protocol version of the sent message.
	Version uint32 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *Header) Reset() {
	*x = Header{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Header) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Header) ProtoMessage() {}

func (x *Header) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Header.ProtoReflect.Descriptor instead.
func (*Header) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{1}
}

func (x *Header) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

// AdvertHashes is a message broadcast for inform peers of the node's DAG state.
type AdvertHashes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// currentBlockDate contains a Unix timestamp at which the current block started (UTC).
	CurrentBlockDate uint32 `protobuf:"varint,1,opt,name=currentBlockDate,proto3" json:"currentBlockDate,omitempty"`
	// blocks contains the DAG blocks (as specified in RFC005) except the historic block. The historic block's hash
	// is specified in the `historicHash` field. In this `blocks` field the first entry is the oldest block (after the
	// historic block), the last entry is the current block.
	Blocks []*BlockHashes `protobuf:"bytes,2,rep,name=blocks,proto3" json:"blocks,omitempty"`
	// historicHash contains the XOR of all head hashes leading up to (but not including) the first block.
	HistoricHash []byte `protobuf:"bytes,3,opt,name=historicHash,proto3" json:"historicHash,omitempty"`
}

func (x *AdvertHashes) Reset() {
	*x = AdvertHashes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AdvertHashes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdvertHashes) ProtoMessage() {}

func (x *AdvertHashes) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AdvertHashes.ProtoReflect.Descriptor instead.
func (*AdvertHashes) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{2}
}

func (x *AdvertHashes) GetCurrentBlockDate() uint32 {
	if x != nil {
		return x.CurrentBlockDate
	}
	return 0
}

func (x *AdvertHashes) GetBlocks() []*BlockHashes {
	if x != nil {
		return x.Blocks
	}
	return nil
}

func (x *AdvertHashes) GetHistoricHash() []byte {
	if x != nil {
		return x.HistoricHash
	}
	return nil
}

// BlockHashes contains the head's hashes of a block.
type BlockHashes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// hashes contains the hashes of the heads in this block.
	Hashes [][]byte `protobuf:"bytes,1,rep,name=hashes,proto3" json:"hashes,omitempty"`
}

func (x *BlockHashes) Reset() {
	*x = BlockHashes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BlockHashes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlockHashes) ProtoMessage() {}

func (x *BlockHashes) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlockHashes.ProtoReflect.Descriptor instead.
func (*BlockHashes) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{3}
}

func (x *BlockHashes) GetHashes() [][]byte {
	if x != nil {
		return x.Hashes
	}
	return nil
}

// TransactionListQuery is a message used to query a peer's TransactionList.
type TransactionListQuery struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// blockDate specifies start date of the block (as Unix timestamp, in UTC) which is queried.
	BlockDate uint32 `protobuf:"varint,1,opt,name=blockDate,proto3" json:"blockDate,omitempty"`
}

func (x *TransactionListQuery) Reset() {
	*x = TransactionListQuery{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TransactionListQuery) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TransactionListQuery) ProtoMessage() {}

func (x *TransactionListQuery) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TransactionListQuery.ProtoReflect.Descriptor instead.
func (*TransactionListQuery) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{4}
}

func (x *TransactionListQuery) GetBlockDate() uint32 {
	if x != nil {
		return x.BlockDate
	}
	return 0
}

// TransactionList is the response message for TransactionListQuery.
type TransactionList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// blockDate specifies start date of the block (as Unix timestamp, in UTC) which the transactions belong to.
	BlockDate uint32 `protobuf:"varint,1,opt,name=blockDate,proto3" json:"blockDate,omitempty"`
	// transactions contains the peer's transactions for the specified block.
	Transactions []*Transaction `protobuf:"bytes,10,rep,name=transactions,proto3" json:"transactions,omitempty"`
}

func (x *TransactionList) Reset() {
	*x = TransactionList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TransactionList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TransactionList) ProtoMessage() {}

func (x *TransactionList) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TransactionList.ProtoReflect.Descriptor instead.
func (*TransactionList) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{5}
}

func (x *TransactionList) GetBlockDate() uint32 {
	if x != nil {
		return x.BlockDate
	}
	return 0
}

func (x *TransactionList) GetTransactions() []*Transaction {
	if x != nil {
		return x.Transactions
	}
	return nil
}

// Transaction represents a transaction on the DAG.
type Transaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// hash contains the reference of the transaction, as specified by RFC004.
	Hash []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	// data contains the data of the transaction, which is a JWS as specified by RFC004.
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *Transaction) Reset() {
	*x = Transaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Transaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Transaction) ProtoMessage() {}

func (x *Transaction) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Transaction.ProtoReflect.Descriptor instead.
func (*Transaction) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{6}
}

func (x *Transaction) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

func (x *Transaction) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

// TransactionPayloadQuery is a message used to query the payload of a transaction.
type TransactionPayloadQuery struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// payloadHash contains the SHA-256 hash of the payload which the node would like to receive, as specified by RFC004.
	PayloadHash []byte `protobuf:"bytes,1,opt,name=payloadHash,proto3" json:"payloadHash,omitempty"`
}

func (x *TransactionPayloadQuery) Reset() {
	*x = TransactionPayloadQuery{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TransactionPayloadQuery) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TransactionPayloadQuery) ProtoMessage() {}

func (x *TransactionPayloadQuery) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TransactionPayloadQuery.ProtoReflect.Descriptor instead.
func (*TransactionPayloadQuery) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{7}
}

func (x *TransactionPayloadQuery) GetPayloadHash() []byte {
	if x != nil {
		return x.PayloadHash
	}
	return nil
}

// TransactionPayload is the response message for TransactionPayloadQuery.
type TransactionPayload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// payloadHash contains the SHA-256 hash of the payload, as specified by RFC004.
	PayloadHash []byte `protobuf:"bytes,1,opt,name=payloadHash,proto3" json:"payloadHash,omitempty"`
	// data contains the actual payload.
	Data []byte `protobuf:"bytes,10,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *TransactionPayload) Reset() {
	*x = TransactionPayload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_network_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TransactionPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TransactionPayload) ProtoMessage() {}

func (x *TransactionPayload) ProtoReflect() protoreflect.Message {
	mi := &file_transport_network_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TransactionPayload.ProtoReflect.Descriptor instead.
func (*TransactionPayload) Descriptor() ([]byte, []int) {
	return file_transport_network_proto_rawDescGZIP(), []int{8}
}

func (x *TransactionPayload) GetPayloadHash() []byte {
	if x != nil {
		return x.PayloadHash
	}
	return nil
}

func (x *TransactionPayload) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

var File_transport_network_proto protoreflect.FileDescriptor

var file_transport_network_proto_rawDesc = []byte{
	0x0a, 0x17, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6e, 0x65, 0x74, 0x77,
	0x6f, 0x72, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x74, 0x72, 0x61, 0x6e, 0x73,
	0x70, 0x6f, 0x72, 0x74, 0x22, 0xb0, 0x03, 0x0a, 0x0e, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x3d, 0x0a, 0x0c, 0x61, 0x64, 0x76, 0x65, 0x72,
	0x74, 0x48, 0x61, 0x73, 0x68, 0x65, 0x73, 0x18, 0x64, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x41, 0x64, 0x76, 0x65, 0x72, 0x74,
	0x48, 0x61, 0x73, 0x68, 0x65, 0x73, 0x48, 0x00, 0x52, 0x0c, 0x61, 0x64, 0x76, 0x65, 0x72, 0x74,
	0x48, 0x61, 0x73, 0x68, 0x65, 0x73, 0x12, 0x55, 0x0a, 0x14, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x18, 0x65,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74,
	0x51, 0x75, 0x65, 0x72, 0x79, 0x48, 0x00, 0x52, 0x14, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x46, 0x0a,
	0x0f, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74,
	0x18, 0x66, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69,
	0x73, 0x74, 0x48, 0x00, 0x52, 0x0f, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x5e, 0x0a, 0x17, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x18, 0x67, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61,
	0x79, 0x6c, 0x6f, 0x61, 0x64, 0x51, 0x75, 0x65, 0x72, 0x79, 0x48, 0x00, 0x52, 0x17, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x4f, 0x0a, 0x12, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x68, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1d, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x54, 0x72,
	0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x48, 0x00, 0x52, 0x12, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x42, 0x09, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x4a, 0x04, 0x08, 0x01, 0x10, 0x64, 0x22, 0x22, 0x0a, 0x06, 0x48, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x8e, 0x01, 0x0a, 0x0c,
	0x41, 0x64, 0x76, 0x65, 0x72, 0x74, 0x48, 0x61, 0x73, 0x68, 0x65, 0x73, 0x12, 0x2a, 0x0a, 0x10,
	0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x42,
	0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x65, 0x12, 0x2e, 0x0a, 0x06, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x61, 0x73, 0x68, 0x65, 0x73,
	0x52, 0x06, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x12, 0x22, 0x0a, 0x0c, 0x68, 0x69, 0x73, 0x74,
	0x6f, 0x72, 0x69, 0x63, 0x48, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c,
	0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x69, 0x63, 0x48, 0x61, 0x73, 0x68, 0x22, 0x25, 0x0a, 0x0b,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x61, 0x73, 0x68, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x68,
	0x61, 0x73, 0x68, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x68, 0x61, 0x73,
	0x68, 0x65, 0x73, 0x22, 0x34, 0x0a, 0x14, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x1c, 0x0a, 0x09, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09,
	0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x65, 0x22, 0x6b, 0x0a, 0x0f, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09,
	0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x09, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x65, 0x12, 0x3a, 0x0a, 0x0c, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x16, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0c, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x35, 0x0a, 0x0b, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74,
	0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x3b, 0x0a,
	0x17, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c,
	0x6f, 0x61, 0x64, 0x51, 0x75, 0x65, 0x72, 0x79, 0x12, 0x20, 0x0a, 0x0b, 0x70, 0x61, 0x79, 0x6c,
	0x6f, 0x61, 0x64, 0x48, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x48, 0x61, 0x73, 0x68, 0x22, 0x4a, 0x0a, 0x12, 0x54, 0x72,
	0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x12, 0x20, 0x0a, 0x0b, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x48, 0x61, 0x73, 0x68, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x48, 0x61,
	0x73, 0x68, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x32, 0x50, 0x0a, 0x07, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x12, 0x45, 0x0a, 0x07, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x12, 0x19, 0x2e, 0x74,
	0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x19, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x42, 0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6e, 0x75, 0x74, 0x73, 0x2d, 0x66, 0x6f, 0x75, 0x6e,
	0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6e, 0x75, 0x74, 0x73, 0x2d, 0x6e, 0x6f, 0x64, 0x65,
	0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f,
	0x72, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_transport_network_proto_rawDescOnce sync.Once
	file_transport_network_proto_rawDescData = file_transport_network_proto_rawDesc
)

func file_transport_network_proto_rawDescGZIP() []byte {
	file_transport_network_proto_rawDescOnce.Do(func() {
		file_transport_network_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_network_proto_rawDescData)
	})
	return file_transport_network_proto_rawDescData
}

var file_transport_network_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_transport_network_proto_goTypes = []interface{}{
	(*NetworkMessage)(nil),          // 0: transport.NetworkMessage
	(*Header)(nil),                  // 1: transport.Header
	(*AdvertHashes)(nil),            // 2: transport.AdvertHashes
	(*BlockHashes)(nil),             // 3: transport.BlockHashes
	(*TransactionListQuery)(nil),    // 4: transport.TransactionListQuery
	(*TransactionList)(nil),         // 5: transport.TransactionList
	(*Transaction)(nil),             // 6: transport.Transaction
	(*TransactionPayloadQuery)(nil), // 7: transport.TransactionPayloadQuery
	(*TransactionPayload)(nil),      // 8: transport.TransactionPayload
}
var file_transport_network_proto_depIdxs = []int32{
	2, // 0: transport.NetworkMessage.advertHashes:type_name -> transport.AdvertHashes
	4, // 1: transport.NetworkMessage.TransactionListQuery:type_name -> transport.TransactionListQuery
	5, // 2: transport.NetworkMessage.TransactionList:type_name -> transport.TransactionList
	7, // 3: transport.NetworkMessage.transactionPayloadQuery:type_name -> transport.TransactionPayloadQuery
	8, // 4: transport.NetworkMessage.transactionPayload:type_name -> transport.TransactionPayload
	3, // 5: transport.AdvertHashes.blocks:type_name -> transport.BlockHashes
	6, // 6: transport.TransactionList.transactions:type_name -> transport.Transaction
	0, // 7: transport.Network.Connect:input_type -> transport.NetworkMessage
	0, // 8: transport.Network.Connect:output_type -> transport.NetworkMessage
	8, // [8:9] is the sub-list for method output_type
	7, // [7:8] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_transport_network_proto_init() }
func file_transport_network_proto_init() {
	if File_transport_network_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transport_network_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NetworkMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_network_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Header); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_network_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AdvertHashes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_network_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BlockHashes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_network_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TransactionListQuery); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_network_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TransactionList); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_network_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Transaction); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_network_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TransactionPayloadQuery); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_network_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TransactionPayload); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_transport_network_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*NetworkMessage_AdvertHashes)(nil),
		(*NetworkMessage_TransactionListQuery)(nil),
		(*NetworkMessage_TransactionList)(nil),
		(*NetworkMessage_TransactionPayloadQuery)(nil),
		(*NetworkMessage_TransactionPayload)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_transport_network_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_transport_network_proto_goTypes,
		DependencyIndexes: file_transport_network_proto_depIdxs,
		MessageInfos:      file_transport_network_proto_msgTypes,
	}.Build()
	File_transport_network_proto = out.File
	file_transport_network_proto_rawDesc = nil
	file_transport_network_proto_goTypes = nil
	file_transport_network_proto_depIdxs = nil
}
