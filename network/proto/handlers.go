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
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	log "github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

func (p *protocol) handleAdvertHashes(peer p2p.PeerID, advertHash *transport.AdvertHashes) {
	log.Logger().Tracef("Received adverted hashes from peer: %s", peer)

	localBlocks := p.blocks.Get()
	// We could theoretically support clock skew of peers (compared to the local clock), but we can also just wait for
	// the blocks to synchronize which is way easier. It could just lead to a little synchronization delay at midnight.
	if getBlockTimestamp(getCurrentBlock(localBlocks)) != advertHash.CurrentBlockDate {
		// Log level is INFO which might prove to be too verbose, but we'll have to find out in an actual network.
		log.Logger().Infof("Peer's current block date differs (probably due to clock skew) which is not supported, broadcast is ignored (peer=%s)", peer)
		return
	}
	// Block count is spec'd, so they must not differ.
	if len(localBlocks) - 1 != len(advertHash.Blocks) {
		log.Logger().Warnf("Peer's number of block differs which is not supported, broadcast is ignored (peer=%s)", peer)
		return
	}
	localHistoryHash := getHistoricBlock(localBlocks).XORHeads()
	if !localHistoryHash.Equals(hash.FromSlice(advertHash.HistoricHash)) {
		log.Logger().Warnf("Peer's historic block differs, broadcast is ignored (peer=%s)", peer)
		return
	}

	for i := 1; i < len(localBlocks); i++ {
		localBlock := localBlocks[i]
		peerBlock := advertHash.Blocks[i - 1]
		for _, peerHead := range peerBlock.Hashes {
			peerHeadHash := hash.FromSlice(peerHead)
			headMatches := false
			for _, localHead := range localBlock.Heads {
				if peerHeadHash.Equals(localHead) {
					headMatches = true
					break
				}
			}
			if headMatches {
				continue
			}
			// peerHead is not one of our heads in the same block, which either means:
			// - Peer has a TX we don't have
			// - We have a TX our peer doesn't have
			// To find out which is the case we check whether we have the peer's head as TX on our DAG.
			// If not, we're missing the peer's TX on our DAG and should query the block.
			headIsPresentOnLocalDAG, err := p.graph.IsPresent(peerHeadHash)
			if err != nil {
				log.Logger().Errorf("Error while checking peer head on local DAG (ref=%s): %v", peerHeadHash, err)
			} else if !headIsPresentOnLocalDAG {
				log.Logger().Infof("Peer has head which is not present on our DAG, querying block transactions (peer=%s)", peer)
				go p.queryTransactionList(peer)
			}
		}
	}

	// TODO: Update to XOR of all heads?
	// p.newPeerHashChannel <- peerHash
}

func (p protocol) queryTransactionList(peer p2p.PeerID) {
	msg := createMessage()
	msg.Message = &transport.NetworkMessage_TransactionListQuery{TransactionListQuery: &transport.TransactionListQuery{}}
	if err := p.p2pNetwork.Send(peer, &msg); err != nil {
		log.Logger().Warnf("Unable to query peer for hash list (peer=%s): %v", peer, err)
	}
}

func (p protocol) advertHashes() {
	msg := createMessage()
	blocks := p.blocks.Get()
	protoBlocks := make([]*transport.BlockHashes, len(blocks) - 1)
	for blockIdx, currBlock := range blocks {
		// First block = historic block, which isn't added in full but as XOR of its heads
		if blockIdx > 0 {
			protoBlocks[blockIdx - 1] = &transport.BlockHashes{Hashes: make([][]byte, len(currBlock.Heads))}
			for headIdx, currHead := range currBlock.Heads {
				protoBlocks[blockIdx - 1].Hashes[headIdx] = currHead.Slice()
			}
		}
	}
	if log.Logger().Level >= logrus.TraceLevel {
		// DAGBlock.String() is expensive
		log.Logger().Tracef("Broadcasting heads: %s", blocks)
	}
	historicBlock := getHistoricBlock(blocks) // First block is historic block
	currentBlock := getCurrentBlock(blocks)   // Last block is current block
	msg.Message = &transport.NetworkMessage_AdvertHashes{AdvertHashes: &transport.AdvertHashes{
		Blocks:           protoBlocks,
		HistoricHash:     historicBlock.XORHeads().Slice(),
		CurrentBlockDate: getBlockTimestamp(currentBlock),
	}}
	p.p2pNetwork.Broadcast(&msg)
}


func (p *protocol) handleTransactionPayload(peer p2p.PeerID, contents *transport.TransactionPayload) {
	payloadHash := hash.FromSlice(contents.PayloadHash)
	log.Logger().Infof("Received transaction payload from peer (peer=%s,payloadHash=%s,len=%d)", peer, payloadHash, len(contents.Data))
	// TODO: Maybe this should be asynchronous since writing the transaction contents might be I/O heavy?
	if transaction, err := p.graph.GetByPayloadHash(payloadHash); err != nil {
		log.Logger().Errorf("Error while looking up transaction to write payload (payloadHash=%s): %v", payloadHash, err)
	} else if transaction == nil {
		// This might mean an attacker is sending us unsolicited document payloads
		log.Logger().Infof("Received transaction payload for transaction we don't have (payloadHash=%s)", payloadHash)
	} else if hasPayload, err := p.payloadStore.IsPresent(payloadHash); err != nil {
		log.Logger().Errorf("Error while checking whether we already have payload (payloadHash=%s): %v", payloadHash, err)
	} else if hasPayload {
		log.Logger().Debugf("Received payload we already have (payloadHash=%s)", payloadHash)
	} else if err := p.payloadStore.WritePayload(payloadHash, contents.Data); err != nil {
		log.Logger().Errorf("Error while writing payload for transaction (hash=%s): %v", payloadHash, err)
	} else {
		// TODO: Publish change to subscribers
	}
}

func (p *protocol) handleTransactionPayloadQuery(peer p2p.PeerID, query *transport.TransactionPayloadQuery) error {
	payloadHash := hash.FromSlice(query.PayloadHash)
	log.Logger().Tracef("Received transaction payload query from peer (peer=%s, payloadHash=%s)", peer, payloadHash)
	// TODO: Maybe this should be asynchronous since loading transaction contents might be I/O heavy?
	if data, err := p.payloadStore.ReadPayload(payloadHash); err != nil {
		return err
	} else if data != nil {
		responseMsg := createMessage()
		responseMsg.Message = &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{
			PayloadHash: payloadHash.Slice(),
			Data:        data,
		}}
		if err := p.p2pNetwork.Send(peer, &responseMsg); err != nil {
			return err
		}
	} else {
		// TODO: Send empty response message when we don't have the payload
		log.Logger().Infof("Peer queried us for transaction payload, but seems like we don't have it (peer=%s,payloadHash=%s)", peer, payloadHash)
	}
	return nil
}

func (p *protocol) handleTransactionList(peer p2p.PeerID, transactionList *transport.TransactionList) error {
	log.Logger().Tracef("Received transaction list from peer (peer=%s)", peer)
	for _, current := range transactionList.Transactions {
		transactionRef := hash.FromSlice(current.Hash)
		if !transactionRef.Equals(hash.SHA256Sum(current.Data)) {
			log.Logger().Warn("Received transaction hash doesn't match transaction bytes, skipping.")
			continue
		}
		if err := p.checkTransactionOnLocalNode(peer, transactionRef, current.Data); err != nil {
			log.Logger().Errorf("Error while checking peer transaction on local node (peer=%s, transaction=%s): %v", peer, transactionRef, err)
		}
	}
	return nil
}

// checkTransactionOnLocalNode checks whether the given transaction is present on the local node, adds it if not and/or queries
// the payload if it (the payload) it not present. If we have both transaction and payload, nothing is done.
func (p *protocol) checkTransactionOnLocalNode(peer p2p.PeerID, transactionRef hash.SHA256Hash, data []byte) error {
	// TODO: Make this a bit smarter.
	var transaction dag.Transaction
	var err error
	if transaction, err = dag.ParseTransaction(data); err != nil {
		return fmt.Errorf("received transaction is invalid (peer=%s,pref=%s): %w", peer, transactionRef, err)
	}
	queryContents := false
	if present, err := p.graph.IsPresent(transactionRef); err != nil {
		return err
	} else if !present {
		if err := p.signatureVerifier.Verify(transaction); err != nil {
			return fmt.Errorf("not adding received transaction to DAG, invalid signature (ref=%s): %w", transaction.Ref(), err)
		}
		if err := p.graph.Add(transaction); err != nil {
			return fmt.Errorf("unable to add received transaction to DAG: %w", err)
		}
		queryContents = true
	} else if payloadPresent, err := p.payloadStore.IsPresent(transaction.PayloadHash()); err != nil {
		return err
	} else {
		queryContents = !payloadPresent
	}
	if queryContents {
		// TODO: Currently we send the query to the peer that sent us the hash, but this peer might not have the
		//   transaction contents. We need a smarter way to get it from a peer who does.
		log.Logger().Infof("Received transaction hash from peer that we don't have yet or we're missing its contents, will query it (peer=%s,hash=%s)", peer, transactionRef)
		responseMsg := createMessage()
		responseMsg.Message = &transport.NetworkMessage_TransactionPayloadQuery{
			TransactionPayloadQuery: &transport.TransactionPayloadQuery{PayloadHash: transaction.PayloadHash().Slice()},
		}
		return p.p2pNetwork.Send(peer, &responseMsg)
	}
	return nil
}

func (p *protocol) handleTransactionListQuery(peer p2p.PeerID) error {
	log.Logger().Tracef("Received transaction list query from peer (peer=%s)", peer)
	transactions, err := p.graph.All()
	if err != nil {
		return err
	}
	tl := &transport.TransactionList{
		Transactions: make([]*transport.Transaction, len(transactions)),
	}
	for i, transaction := range transactions {
		tl.Transactions[i] = &transport.Transaction{
			Hash: transaction.Ref().Slice(),
			Data: transaction.Data(),
		}
	}
	msg := createMessage()
	msg.Message = &transport.NetworkMessage_TransactionList{TransactionList: tl}
	if err := p.p2pNetwork.Send(peer, &msg); err != nil {
		return err
	}
	return nil
}

func getBlockTimestamp(currentBlock DAGBlock) uint32 {
	return uint32(currentBlock.Start.UTC().Unix())
}

func getCurrentBlock(blocks []DAGBlock) DAGBlock {
	return blocks[len(blocks)-1]
}

func getHistoricBlock(blocks []DAGBlock) DAGBlock {
	return blocks[0]
}