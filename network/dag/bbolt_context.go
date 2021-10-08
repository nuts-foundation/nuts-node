package dag

import (
	"context"
	"errors"
	"go.etcd.io/bbolt"
)

var bboltTXContextKey = struct{}{}

type bboltTXCallback func(contextWithTX context.Context, tx *bbolt.Tx) error

// bboltTXView executes the given callback in a read-only BBolt transaction. It attempts to re-use the active transaction from the given context, if there is one.
// If there's no active transaction a new one will be started.
func bboltTXView(ctx context.Context, db *bbolt.DB, cb bboltTXCallback) error {
	return callBBoltCallbackWithTX(ctx, db, cb, false)
}

// bboltTXUpdate executes the given callback in a writable BBolt transaction. It attempts to re-use the active transaction from the given context, if there is one.
// If there's no active transaction a new one will be started.
// If there's an active transaction which is readonly an error will be returned.
func bboltTXUpdate(ctx context.Context, db *bbolt.DB, cb bboltTXCallback) error {
	return callBBoltCallbackWithTX(ctx, db, cb, true)
}

func callBBoltCallbackWithTX(ctx context.Context, db *bbolt.DB, cb bboltTXCallback, writable bool) error {
	tx, txIsActive := ctx.Value(bboltTXContextKey).(*bbolt.Tx)
	if !txIsActive {
		// No active TX, we can simply start one here as long as we put it in the context we pass down, allowing nested BBolt database callers to re-use the transaction.
		if writable {
			return db.Update(func(tx *bbolt.Tx) error {
				return cb(context.WithValue(ctx, bboltTXContextKey, tx), tx)
			})
		}
		return db.View(func(tx *bbolt.Tx) error {
			return cb(context.WithValue(ctx, bboltTXContextKey, tx), tx)
		})
	}
	// There is an active TX we can use. We just have to check whether it's writable if we need it writable.
	if writable && !tx.Writable() {
		return errors.New("the active BBolt transaction is not writable")
	}
	return cb(ctx, tx)
}
