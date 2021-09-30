package dag

import "go.etcd.io/bbolt"

func copyBBoltValue(bucket *bbolt.Bucket, key []byte) []byte {
	val := bucket.Get(key)
	// Because things will go terribly wrong when you use a []byte returned by BBolt outside its transaction,
	// we want to make sure to work with a copy.
	//
	// This seems to be the best (and shortest) way to copy a byte slice:
	// https://github.com/go101/go101/wiki/How-to-perfectly-clone-a-slice%3F
	return append(val[:0:0], val...)
}
