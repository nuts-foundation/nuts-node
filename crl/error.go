package crl

import (
	"fmt"
	"strings"
)

type SyncError struct {
	errors []error
}

func (err *SyncError) Errors() []error {
	return err.errors
}

func (err *SyncError) Error() string {
	var summary []string

	for _, inner := range err.errors {
		summary = append(summary, inner.Error())
	}

	return fmt.Sprintf("synchronization failed: %s", strings.Join(summary, ", "))
}
