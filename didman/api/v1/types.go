package v1

import (
	"github.com/nuts-foundation/nuts-node/didman"
	"schneider.vip/problem"
)

// Error is an alias for the internally used problem.Problem
type Error = problem.Problem

// ContactInformation is an alias for the already defined didman.ContactInformation
type ContactInformation = didman.ContactInformation