package main

import (
	"sort"
	"testing"
)

func TestKeyList(t *testing.T) {
	got := KeyList{
		[]rstValue{{value: "storage.bbolt.backup.directory"}},
		[]rstValue{{value: "storage.bbolt.backup.interval"}},
		[]rstValue{{value: "storage.redis.address"}},
		[]rstValue{{value: "storage.redis.database"}},
		[]rstValue{{value: "storage.redis.password"}},
		[]rstValue{{value: "storage.redis.sentinel.master"}},
		[]rstValue{{value: "storage.redis.sentinel.nodes"}},
		[]rstValue{{value: "storage.redis.sentinel.password"}},
		[]rstValue{{value: "storage.redis.sentinel.username"}},
		[]rstValue{{value: "storage.redis.tls.truststorefile"}},
		[]rstValue{{value: "storage.redis.username"}},
	}

	want := KeyList{
		[]rstValue{{value: "storage.bbolt.backup.directory"}},
		[]rstValue{{value: "storage.bbolt.backup.interval"}},
		[]rstValue{{value: "storage.redis.address"}},
		[]rstValue{{value: "storage.redis.database"}},
		[]rstValue{{value: "storage.redis.password"}},
		[]rstValue{{value: "storage.redis.username"}},
		[]rstValue{{value: "storage.redis.sentinel.master"}},
		[]rstValue{{value: "storage.redis.sentinel.nodes"}},
		[]rstValue{{value: "storage.redis.sentinel.password"}},
		[]rstValue{{value: "storage.redis.sentinel.username"}},
		[]rstValue{{value: "storage.redis.tls.truststorefile"}},
	}
	if len(got) != len(want) {
		t.Fatal("sample set length mismatch")
	}

	sort.Sort(got)
	for i := range got {
		if got[i][0].value != want[i][0].value {
			t.Errorf("[%d] got %q, want %q", i, got[i][0].value, want[i][0].value)
		}
	}
}
