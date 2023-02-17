/*
 * Copyright (C) 2022 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package core

const (
	// LogFieldModule is the log field for the module name.
	LogFieldModule = "module"

	// LogFieldEventType is the log field key for event types from the events module.
	LogFieldEventType = "eventType"
	// LogFieldEventSubject is the log field key for event subjects from the events module.
	LogFieldEventSubject = "eventSubject"
	// LogFieldEventSubscriber is the log field key for event subscribers from the events module.
	LogFieldEventSubscriber = "eventSubscriber"

	// LogFieldCredentialID is the log field key for the ID of a Verifiable Credential from the VCR module.
	LogFieldCredentialID = "credentialID"
	// LogFieldCredentialType is the log field key for the type of a Verifiable Credential from the VCR module.
	LogFieldCredentialType = "credentialType"
	// LogFieldCredentialIssuer is the log field key for the issuer of a Verifiable Credential from the VCR module.
	LogFieldCredentialIssuer = "credentialIssuer"

	// LogFieldStore is the log field key for the name of a store managed by the storage module.
	LogFieldStore = "store"
	// LogFieldStoreShelf is the log field key for the name of a shelf, in a store managed by the storage module.
	LogFieldStoreShelf = "storeShelf"

	// LogFieldKeyID is the log field key for the unique ID of a key from the VDR or crypto module.
	LogFieldKeyID = "keyID"

	// LogFieldDID is the log field key for the ID of a DID document from the VDR module.
	LogFieldDID = "did"
	// LogFieldServiceID is the log field key for the ID of a DID document service from the VDR module.
	LogFieldServiceID = "serviceID"
	// LogFieldServiceType is the log field key for the type of a DID document service from the VDR module.
	LogFieldServiceType = "serviceType"
	// LogFieldServiceEndpoint is the log field key of the ID of the endpoint of a DID document service from the VDR module.
	LogFieldServiceEndpoint = "serviceEndpoint"

	// LogFieldAuthorizerDID is the log field key for the DID of the authorizer when creating an access token in the auth module.
	LogFieldAuthorizerDID = "authorizerDID"
	// LogFieldRequesterDID is the log field key for the DID of the requester when creating an access token in the auth module.
	LogFieldRequesterDID = "requesterDID"

	// LogFieldNodeAddress is the log field key for node's (gRPC) address from the network module.
	LogFieldNodeAddress = "nodeAddr"
	// LogFieldProtocolVersion is the log field key for the protocol version from the network module.
	LogFieldProtocolVersion = "protocolVersion"
	// LogFieldMessageType is the log field key for the type, of a received/sent message from the network module.
	LogFieldMessageType = "messageType"
	// LogFieldConversationID is the log field key for the conversation ID of messages from the network module.
	LogFieldConversationID = "conversationID"
	// LogFieldPeerID is the log field key for peer IDs from the network module.
	LogFieldPeerID = "peerID"
	// LogFieldPeerAddr is the log field key for peer addresses from the network module.
	LogFieldPeerAddr = "peerAddr"
	// LogFieldPeerIP is the log field key for peer IP addresses extracted from the stream.
	LogFieldPeerIP = "peerIP"
	// LogFieldPeerNodeDID is the log field key for a peer's node DID from the network module.
	LogFieldPeerNodeDID = "peerDID"
	// LogFieldPeerAuthenticated is the log field key for that indicates if the peer's node DID is authenticated.
	LogFieldPeerAuthenticated = "peerAuthenticated"
	// LogFieldTransactionRef is the log field key for a transaction reference from the network module.
	LogFieldTransactionRef = "txRef"
	// LogFieldTransactionType is the log field key for the payload type, of a transaction from the network module.
	LogFieldTransactionType = "txType"
	// LogFieldTransactionIsPrivate is the log field key for marker whether a transaction is private, from the network module.
	LogFieldTransactionIsPrivate = "txIsPrivate"
	// LogFieldTransactionPayloadHash is the log field key for the payload (hash) of a transaction from the network module.
	LogFieldTransactionPayloadHash = "txPayloadHash"
	// LogFieldTransactionPayloadLength is the log field key for the payload (length in bytes) of a transaction from the network module.
	LogFieldTransactionPayloadLength = "txPayloadLen"

	// LogFieldAuditSubject is the log field of the subject (e.g. DID, DID document service, etc) of an audit event.
	LogFieldAuditSubject = "subject"
)
