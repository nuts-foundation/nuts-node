package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type Predicate func() (bool, error)

func WaitFor(t *testing.T, p Predicate, timeout time.Duration, message string, msgArgs ...interface{}) bool {
	deadline := time.Now().Add(timeout)
	for {
		b, err := p()
		if !assert.NoError(t, err) {
			return false
		}
		if b {
			return true
		}
		if time.Now().After(deadline) {
			assert.Fail(t, fmt.Sprintf(message, msgArgs...))
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}
