/*
 * Copyright (C) 2021. Nuts community
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

package proto

import (
	"fmt"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	log "github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

func (p *protocol) handleAdvertHashes(peer p2p.PeerID, advertHash *transport.AdvertHashes) {
	log.Logger().Tracef("Received adverted hash from peer: %s", peer)
	hashes := make([]hash.SHA256Hash, len(advertHash.Hashes))
	for i, h := range advertHash.Hashes {
		hashes[i] = hash.FromSlice(h)
	}
	peerHash := PeerHash{
		Peer:   peer,
		Hashes: hashes,
	}
	p.newPeerHashChannel <- peerHash

	heads := p.graph.Heads()
	for _, peerHash := range hashes {
		found := false
		for _, head := range heads {
			if peerHash.Equals(head) {
				found = true
				break
			}
		}
		if !found {
			log.Logger().Infof("Peer has different heads than us, querying document list (peer=%s)", peer)
			go p.queryDocumentList(peer)
			return
		}
	}
}

func (p protocol) queryDocumentList(peer p2p.PeerID) {
	msg := createMessage()
	msg.DocumentListQuery = &transport.DocumentListQuery{}
	if err := p.p2pNetwork.Send(peer, &msg); err != nil {
		log.Logger().Errorf("Unable to query peer for hash list (peer=%s): %v", peer, err)
	}
}

func (p protocol) advertHashes() {
	msg := createMessage()
	heads := p.graph.Heads()
	slices := make([][]byte, len(heads))
	for i, hash := range heads {
		slices[i] = hash.Slice()
	}
	log.Logger().Tracef("Broadcasting heads: %v", heads)
	msg.AdvertHashes = &transport.AdvertHashes{Hashes: slices}
	p.p2pNetwork.Broadcast(&msg)
}

func (p *protocol) handleDocumentPayload(peer p2p.PeerID, contents *transport.DocumentPayload) {
	payloadHash := hash.FromSlice(contents.PayloadHash)
	log.Logger().Infof("Received document payload from peer (peer=%s,payloadHash=%s,len=%d)", peer, payloadHash, len(contents.Data))
	// TODO: Maybe this should be asynchronous since writing the document contents might be I/O heavy?
	if document, err := p.graph.GetByPayloadHash(payloadHash); err != nil {
		log.Logger().Errorf("Error while looking up document to write payload (payloadHash=%s): %v", payloadHash, err)
	} else if document == nil {
		log.Logger().Warnf("Received document payload for document we don't have (payloadHash=%s)", payloadHash)
	} else if hasPayload, err := p.payloadStore.IsPresent(payloadHash); err != nil {
		log.Logger().Errorf("Error while checking whether we already have payload (payloadHash=%s): %v", payloadHash, err)
	} else if hasPayload {
		log.Logger().Debugf("Received payload we already have (payloadHash=%s)", payloadHash)
	} else if err := p.payloadStore.WritePayload(payloadHash, contents.Data); err != nil {
		log.Logger().Errorf("Error while writing payload for document (hash=%s): %v", payloadHash, err)
	} else {
		// TODO: Publish change to subscribers
	}
}

func (p *protocol) handleDocumentPayloadQuery(peer p2p.PeerID, query *transport.DocumentPayloadQuery) error {
	payloadHash := hash.FromSlice(query.PayloadHash)
	log.Logger().Tracef("Received document payload query from peer (peer=%s, payloadHash=%s)", peer, payloadHash)
	// TODO: Maybe this should be asynchronous since loading document contents might be I/O heavy?
	if data, err := p.payloadStore.ReadPayload(payloadHash); err != nil {
		return err
	} else if data != nil {
		responseMsg := createMessage()
		responseMsg.DocumentPayload = &transport.DocumentPayload{
			PayloadHash: payloadHash.Slice(),
			Data:        data,
		}
		if err := p.p2pNetwork.Send(peer, &responseMsg); err != nil {
			return err
		}
	} else {
		log.Logger().Warnf("Peer queried us for document payload, but seems like we don't have it (peer=%s,payloadHash=%s)", peer, payloadHash)
	}
	return nil
}

func (p *protocol) handleDocumentList(peer p2p.PeerID, documentList *transport.DocumentList) error {
	log.Logger().Tracef("Received document list from peer (peer=%s)", peer)
	for _, current := range documentList.Documents {
		documentRef := hash.FromSlice(current.Hash)
		if !documentRef.Equals(hash.SHA256Sum(current.Data)) {
			log.Logger().Warn("Received document hash doesn't match document bytes, skipping.")
			continue
		}
		if err := p.checkDocumentOnLocalNode(peer, documentRef, current.Data); err != nil {
			log.Logger().Errorf("Error while checking peer document on local node (peer=%s, document=%s): %v", peer, documentRef, err)
		}
	}
	return nil
}

// checkDocumentOnLocalNode checks whether the given document is present on the local node, adds it if not and/or queries
// the payload if it (the payload) it not present. If we have both document and payload, nothing is done.
func (p *protocol) checkDocumentOnLocalNode(peer p2p.PeerID, documentRef hash.SHA256Hash, data []byte) error {
	// TODO: Make this a bit smarter.
	var document dag.Document
	var err error
	if document, err = dag.ParseDocument(data); err != nil {
		return fmt.Errorf("received document is invalid (peer=%s,pref=%s): %w", peer, documentRef, err)
	}
	queryContents := false
	if present, err := p.graph.IsPresent(documentRef); err != nil {
		return err
	} else if !present {
		if err := p.signatureVerifier.Verify(document); err != nil {
			return fmt.Errorf("not adding received document to DAG, invalid signature (ref=%s): %w", document.Ref(), err)
		}
		if err := p.graph.Add(document); err != nil {
			return fmt.Errorf("unable to add received document to DAG: %w", err)
		}
		queryContents = true
	} else if payloadPresent, err := p.payloadStore.IsPresent(document.PayloadHash()); err != nil {
		return err
	} else {
		queryContents = !payloadPresent
	}
	if queryContents {
		// TODO: Currently we send the query to the peer that sent us the hash, but this peer might not have the
		//   document contents. We need a smarter way to get it from a peer who does.
		log.Logger().Infof("Received document hash from peer that we don't have yet or we're missing its contents, will query it (peer=%s,hash=%s)", peer, documentRef)
		responseMsg := createMessage()
		responseMsg.DocumentPayloadQuery = &transport.DocumentPayloadQuery{PayloadHash: document.PayloadHash().Slice()}
		return p.p2pNetwork.Send(peer, &responseMsg)
	}
	return nil
}

func (p *protocol) handleDocumentListQuery(peer p2p.PeerID) error {
	log.Logger().Tracef("Received document list query from peer (peer=%s)", peer)
	msg := createMessage()
	documents, err := p.graph.All()
	if err != nil {
		return err
	}
	msg.DocumentList = &transport.DocumentList{
		Documents: make([]*transport.Document, len(documents)),
	}
	for i, document := range documents {
		msg.DocumentList.Documents[i] = &transport.Document{
			Hash: document.Ref().Slice(),
			Data: document.Data(),
		}
	}
	if err := p.p2pNetwork.Send(peer, &msg); err != nil {
		return err
	}
	return nil
}
