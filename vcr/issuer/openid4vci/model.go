package openid4vci

import "time"

// Flow is an active OpenID4VCI credential issuance flow.
type Flow struct {
	ID string `json:"id"`
	// IssuerID is the identifier of the credential issuer.
	IssuerID string `json:"issuer_id"`
	// WalletID is the identifier of the wallet.
	WalletID string `json:"wallet_id"`
	// Grants is a list of grants that can be used to acquire an access token.
	Grants []Grant `json:"grants"`
	// Credentials is the list of Verifiable Credentials that be issued to the wallet through this flow.
	// It might be pre-determined (in the issuer-initiated flow) or determined during the flow execution (in the wallet-initiated flow).
	Credentials []map[string]interface{} `json:"credentials"`
	Expiry      time.Time                `json:"exp"`
}

// Nonce is a nonce that has been issued for an OpenID4VCI flow, to be used by the wallet when requesting credentials.
// A nonce can only be used once (doh), and is only valid for a certain period of time.
type Nonce struct {
	Nonce  string    `json:"nonce"`
	Expiry time.Time `json:"exp"`
}

// Grant is a grant that has been issued for an OAuth2 state.
type Grant struct {
	// Type is the type of grant, e.g. "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	Type string `json:"type"`
	// Params is a map of parameters for the grant, e.g. "pre-authorized_code" for type "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	Params map[string]interface{} `json:"params"`
}
