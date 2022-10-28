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
