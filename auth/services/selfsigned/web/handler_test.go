package web

import (
	"bytes"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRenderTemplate(t *testing.T) {
	buf := new(bytes.Buffer)
	err := renderTemplate("employee_identity", "nl", types.Session{
		ExpiresAt: time.Now(),
		Contract:  "Hello, World!",
		Secret:    "secret",
		Status:    "pending",
		Employer:  "Darth Vader",
		Employee: types.Employee{
			Identifier: "johndoe@example.com",
			RoleName:   "Administrator",
			Initials:   "J",
			FamilyName: "Doe",
		},
	}, buf)
	require.NoError(t, err)
	println(buf.String())
}
