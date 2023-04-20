package types

type SessionStore interface {
	Store(sessionID string, session Session)
	Load(sessionID string) (Session, bool)
	CheckAndSetStatus(sessionID string, expectedStatus, status string) bool
	Delete(sessionID string)
}

// Session contains the contract text and Session signing Status
type Session struct {
	Contract string
	Secret   string
	Status   string
	Employer string   `json:"employer"`
	Employee Employee `json:"employee"`
}

func (s Session) CredentialSubject() []interface{} {
	person := map[string]string{
		"type":       "Person",
		"initials":   s.Employee.Initials,
		"familyName": s.Employee.FamilyName,
	}
	role := map[string]interface{}{
		"member":     person,
		"roleName":   s.Employee.RoleName,
		"type":       "EmployeeRole",
		"identifier": s.Employee.Identifier,
	}
	credentialSubject := map[string]interface{}{
		"@type":  "Organization",
		"id":     s.Employer,
		"member": role,
	}
	return []interface{}{
		credentialSubject,
	}
}

type Employee struct {
	Identifier string `json:"identifier"`
	RoleName   string `json:"roleName"`
	Initials   string `json:"initials"`
	FamilyName string `json:"familyName"`
}

// SessionCreated represents the session state after creation
const SessionCreated = "created"

// SessionInProgress represents the session state after rendering the html
const SessionInProgress = "in-progress"

// SessionCompleted represents the session state after the user has accepted the contract
const SessionCompleted = "completed"

const SessionCancelled = "cancelled"
