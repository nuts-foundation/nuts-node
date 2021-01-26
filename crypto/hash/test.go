package hash

import "github.com/golang/mock/gomock"

func EqHash(hash SHA256Hash) gomock.Matcher {
	return &hashMatcher{expected: hash}
}

type hashMatcher struct {
	expected SHA256Hash
}

func (h hashMatcher) Matches(x interface{}) bool {
	if actual, ok := x.(SHA256Hash); !ok {
		return false
	} else {
		return actual.Equals(h.expected)
	}
}

func (h hashMatcher) String() string {
	return "Hashes matches: " + h.expected.String()
}
