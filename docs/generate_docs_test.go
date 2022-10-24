package main

import (
	"sort"
	"testing"
)

func TestKeyList(t *testing.T) {
	got := KeyList{
		"storage.bbolt.backup.directory",
		"storage.bbolt.backup.interval",
		"storage.redis.address",
		"storage.redis.database",
		"storage.redis.password",
		"storage.redis.sentinel.master",
		"storage.redis.sentinel.nodes",
		"storage.redis.sentinel.password",
		"storage.redis.sentinel.username",
		"storage.redis.tls.truststorefile",
		"storage.redis.username",
	}

	want := KeyList{
		"storage.bbolt.backup.directory",
		"storage.bbolt.backup.interval",
		"storage.redis.address",
		"storage.redis.database",
		"storage.redis.password",
		"storage.redis.username",
		"storage.redis.sentinel.master",
		"storage.redis.sentinel.nodes",
		"storage.redis.sentinel.password",
		"storage.redis.sentinel.username",
		"storage.redis.tls.truststorefile",
	}
	if len(got) != len(want) {
		t.Fatal("sample set length mismatch")
	}

	sort.Sort(got)
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] got %q, want %q", i, got[i], want[i])
		}
	}
}
