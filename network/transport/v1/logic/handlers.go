/*
 * Copyright (C) 2021 Nuts community
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

package logic

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	"github.com/sirupsen/logrus"
)

func (p *protocol) Handle(peer transport.Peer, raw interface{}) error {
	networkMessage := raw.(*protobuf.NetworkMessage)
	peerID := peer.ID

	switch msg := networkMessage.Message.(type) {
	case *protobuf.NetworkMessage_AdvertHashes:
		if msg.AdvertHashes != nil {
			p.handleAdvertHashes(peerID, msg.AdvertHashes)
		}
	case *protobuf.NetworkMessage_TransactionListQuery:
		if msg.TransactionListQuery != nil {
			return p.handleTransactionListQuery(peerID, msg.TransactionListQuery.BlockDate)
		}
	case *protobuf.NetworkMessage_TransactionList:
		if msg.TransactionList != nil {
			return p.handleTransactionList(peerID, msg.TransactionList)
		}
	case *protobuf.NetworkMessage_TransactionPayloadQuery:
		if msg.TransactionPayloadQuery != nil && msg.TransactionPayloadQuery.PayloadHash != nil {
			return p.handleTransactionPayloadQuery(peerID, msg.TransactionPayloadQuery)
		}
	case *protobuf.NetworkMessage_TransactionPayload:
		if msg.TransactionPayload != nil && msg.TransactionPayload.PayloadHash != nil && msg.TransactionPayload.Data != nil {
			p.handleTransactionPayload(peerID, msg.TransactionPayload)
		}
	case *protobuf.NetworkMessage_DiagnosticsBroadcast:
		p.handleDiagnostics(peerID, msg.DiagnosticsBroadcast)
	default:
		return errors.New("envelope doesn't contain any (handleable) messages")
	}
	return nil
}

func (p *protocol) handleAdvertHashes(peer transport.PeerID, advertHash *protobuf.AdvertHashes) {
	log.Logger().Tracef("Received adverted hashes from peer: %s", peer)

	localBlocks := p.blocks.get()
	// We could theoretically support clock skew of peers (compared to the local clock), but we can also just wait for
	// the blocks to synchronize which is way easier. It could just lead to a little synchronization delay at midnight.
	localCurrentBlockDate := getBlockTimestamp(getCurrentBlock(localBlocks).start)
	if localCurrentBlockDate != advertHash.CurrentBlockDate {
		// Logger level is INFO which might prove to be too verbose, but we'll have to find out in an actual network.
		log.Logger().Infof("Peer's current block date differs (probably due to clock skew) which is not supported, broadcast is ignored (peer=%s,local blockdate=%d,peer blockdate=%d)", peer, localCurrentBlockDate, advertHash.CurrentBlockDate)
		return
	}
	// Block count is spec'd, so they must not differ.
	if len(localBlocks)-1 != len(advertHash.Blocks) {
		log.Logger().Warnf("Peer's number of block differs which is not supported, broadcast is ignored (peer=%s)", peer)
		return
	}
	// Compare historic block
	localHistoricBlock := getHistoricBlock(localBlocks)
	localHistoryHash := localHistoricBlock.xor()
	peerHistoryHash := hash.FromSlice(advertHash.HistoricHash)
	if !localHistoryHash.Equals(peerHistoryHash) {
		// TODO: Disallowed when https://github.com/nuts-foundation/nuts-specification/issues/57 is implemented
		log.Logger().Debugf("Peer's historic block differs which will be sync-ed for now, but will be disallowed in the future (peer=%s,local hash=%s,peer hash=%s)", peer, localHistoryHash, peerHistoryHash)
		p.sender.sendTransactionListQuery(peer, time.Time{})
	} else {
		// Finally, check the rest of the blocks
		p.checkPeerBlocks(peer, advertHash.Blocks, localBlocks[1:])
	}

	// Calculate peer's omnihash and propagate it for diagnostic purposes.
	omnihash := peerHistoryHash
	for _, blck := range advertHash.Blocks {
		for _, head := range blck.Hashes {
			xor(&omnihash, omnihash, hash.FromSlice(head))
		}
	}
	p.peerOmnihashChannel <- PeerOmnihash{
		Peer: peer,
		Hash: omnihash,
	}
}

// checkPeerBlocks compares the blocks we've received from a peer with the ones of the local DAG. If it finds heads in the
// peer blocks that aren't present on the local DAG is will query that block's transactions.
// localBlocks must not include the historic block.
func (p *protocol) checkPeerBlocks(peer transport.PeerID, peerBlocks []*protobuf.BlockHashes, localBlocks []dagBlock) {
	for i := 0; i < len(peerBlocks); i++ {
		localBlock := localBlocks[i]
		peerBlock := peerBlocks[i]
		for _, peerHead := range peerBlock.Hashes {
			peerHeadHash := hash.FromSlice(peerHead)
			headMatches := false
			for _, localHead := range localBlock.heads {
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
			headIsPresentOnLocalDAG, err := p.txState.IsPresent(context.Background(), peerHeadHash)
			if err != nil {
				log.Logger().Errorf("Error while checking peer head on local DAG (ref=%s): %v", peerHeadHash, err)
			} else if !headIsPresentOnLocalDAG {
				log.Logger().Infof("Peer has head which is not present on our DAG, querying block's transactions (peer=%s, tx=%s, blockDate=%s)", peer, peerHeadHash, localBlock.start)
				p.sender.sendTransactionListQuery(peer, localBlock.start)
			}
		}
	}
}

func (p *protocol) handleTransactionPayload(peer transport.PeerID, contents *protobuf.TransactionPayload) {
	payloadHash := hash.FromSlice(contents.PayloadHash)
	ctx := context.Background()
	log.Logger().Infof("Received transaction payload from peer (peer=%s,payloadHash=%s,len=%d)", peer, payloadHash, len(contents.Data))
	if transaction, err := p.txState.GetByPayloadHash(ctx, payloadHash); err != nil {
		log.Logger().Errorf("Error while looking up transaction to write payload (payloadHash=%s): %v", payloadHash, err)
	} else if len(transaction) == 0 {
		// This might mean an attacker is sending us unsolicited document payloads
		log.Logger().Infof("Received transaction payload for transaction we don't have (payloadHash=%s)", payloadHash)
	} else if err := p.txState.WritePayload(ctx, payloadHash, contents.Data); err != nil {
		log.Logger().Errorf("Error while writing payload for transaction (hash=%s): %v", payloadHash, err)
	}
}

func (p *protocol) handleTransactionPayloadQuery(peer transport.PeerID, query *protobuf.TransactionPayloadQuery) error {
	payloadHash := hash.FromSlice(query.PayloadHash)
	log.Logger().Tracef("Received transaction payload query from peer (peer=%s, payloadHash=%s)", peer, payloadHash)

	ctx := context.Background()

	transactions, err := p.txState.GetByPayloadHash(ctx, payloadHash)
	if err != nil {
		return err
	}

	// We need to return an empty payload for transactions with a to address in v1 protocol
	for _, tx := range transactions {
		if len(tx.PAL()) > 0 {
			p.sender.sendTransactionPayload(peer, payloadHash, []byte{})

			return nil
		}
	}

	data, err := p.txState.ReadPayload(ctx, payloadHash)
	if err != nil {
		return err
	}

	if data == nil {
		log.Logger().Debugf("Peer queried us for transaction payload, but seems like we don't have it (peer=%s,payloadHash=%s)", peer, payloadHash)
	}

	p.sender.sendTransactionPayload(peer, payloadHash, data)

	return nil
}

func (p *protocol) handleTransactionList(peer transport.PeerID, transactionList *protobuf.TransactionList) error {
	// TODO: Only process transaction list if we actually queried it (but be aware of pagination)
	// TODO: Do something with blockDate
	log.Logger().Tracef("Received transaction list from peer (peer=%s)", peer)
	ctx := context.Background()
	transactions := transactionList.Transactions
	transactionProcessed := true
	for transactionProcessed {
		transactionProcessed = false
		for i := 0; i < len(transactions); i++ {
			current := transactions[i]
			transactionRef := hash.FromSlice(current.Hash)
			if !transactionRef.Equals(hash.SHA256Sum(current.Data)) {
				return errors.New("received transaction hash doesn't match transaction bytes")
			}
			err := p.checkTransactionOnLocalNode(ctx, peer, transactionRef, current.Data)
			// No error = OK, added to DAG. Remove from list
			if err == nil {
				transactionProcessed = true
				transactions = append(transactions[:i], transactions[i+1:]...)
				i--
				continue
			}
			// If transaction is missing a previous transaction it should be retried later since transactions
			// might have been received out of order. In any other case the response is invalid, so we return.
			if !errors.Is(err, dag.ErrPreviousTransactionMissing) {
				return err
			}
		}
	}
	// There may be transactions left that couldn't be processed
	for _, tx := range transactions {
		log.Logger().Warnf("Received unprocessable transaction because previous transactions are missing (peer=%s,tx=%s)", peer, hash.FromSlice(tx.Hash))
	}
	return nil
}

// checkTransactionOnLocalNode checks whether the given transaction is present on the local node, adds it if not and/or queries
// the payload if it (the payload) it not present. If we have both transaction and payload, nothing is done.
func (p *protocol) checkTransactionOnLocalNode(ctx context.Context, peer transport.PeerID, transactionRef hash.SHA256Hash, data []byte) error {
	// TODO: Make this a bit smarter.
	var transaction dag.Transaction
	var err error

	if transaction, err = dag.ParseTransaction(data); err != nil {
		return fmt.Errorf("received transaction is invalid (peer=%s,pref=%s): %w", peer, transactionRef, err)
	}

	queryContents := false

	if present, err := p.txState.IsPresent(ctx, transactionRef); err != nil {
		return err
	} else if !present {
		if err := p.txState.Add(ctx, transaction, nil); err != nil {
			return fmt.Errorf("unable to add received transaction to DAG (tx=%s): %w", transaction.Ref(), err)
		}
		queryContents = true
	} else if payloadPresent, err := p.txState.IsPayloadPresent(ctx, transaction.PayloadHash()); err != nil {
		return err
	} else {
		queryContents = !payloadPresent
	}

	if queryContents {
		// If the transaction contains a to address, we need to ignore it as it should be handled by the v2 protocol
		if len(transaction.PAL()) > 0 {
			return nil
		}

		// TODO: Currently we send the query to the peer that sent us the hash, but this peer might not have the
		//   transaction contents. We need a smarter way to get it from a peer who does.
		log.Logger().Infof("Received transaction hash from peer that we don't have yet or we're missing its contents, will query it (peer=%s,hash=%s)", peer, transactionRef)
		p.sender.sendTransactionPayloadQuery(peer, transaction.PayloadHash())
	}

	return nil
}

func (p *protocol) handleTransactionListQuery(peer transport.PeerID, blockDateInt uint32) error {
	var startDate time.Time
	var endDate time.Time
	if blockDateInt == 0 {
		// TODO: Disallowed when https://github.com/nuts-foundation/nuts-specification/issues/57 is implemented
		logrus.Debugf("Peer queries historic block which is supported for now, but will be disallowed in the future (peer=%s)", peer)
		// Historic block is queried, query from start up to the first block
		endDate = p.blocks.get()[1].start
	} else {
		startDate = time.Unix(int64(blockDateInt), 0)
		endDate = startDate.AddDate(0, 0, 1)
	}
	log.Logger().Tracef("Received transaction list query from peer (peer=%s,from=%s,to=%s)", peer, startDate, endDate)
	txs, err := p.txState.FindBetween(context.Background(), startDate, endDate)
	if err != nil {
		return err
	}
	p.sender.sendTransactionList(peer, txs, startDate)
	return nil
}

func (p *protocol) handleDiagnostics(peer transport.PeerID, response *protobuf.Diagnostics) {
	diagnostics := transport.Diagnostics{
		Uptime:               time.Duration(response.Uptime) * time.Second,
		NumberOfTransactions: response.NumberOfTransactions,
		SoftwareVersion:      response.SoftwareVersion,
		SoftwareID:           response.SoftwareID,
	}
	for _, peer := range response.Peers {
		diagnostics.Peers = append(diagnostics.Peers, transport.PeerID(peer))
	}
	withLock(p.peerDiagnosticsMutex, func() {
		p.peerDiagnostics[peer] = diagnostics
	})
}

func toNetworkTransactions(transactions []dag.Transaction) []*protobuf.Transaction {
	result := make([]*protobuf.Transaction, len(transactions))
	for i, transaction := range transactions {
		result[i] = &protobuf.Transaction{
			Hash: transaction.Ref().Slice(),
			Data: transaction.Data(),
		}
	}
	return result
}

func getBlockTimestamp(timestamp time.Time) uint32 {
	return uint32(timestamp.Unix())
}

func getCurrentBlock(blocks []dagBlock) dagBlock {
	return blocks[len(blocks)-1]
}

func getHistoricBlock(blocks []dagBlock) dagBlock {
	return blocks[0]
}
