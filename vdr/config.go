package vdr

// ConfDataDir is the config name for specifiying the data location of the requiredFiles
const ConfDataDir = "datadir"

// ConfMode is the config name for the engine mode, server or client
const ConfMode = "mode"

// ConfAddress is the config name for the http server/client address
const ConfAddress = "address"

// ConfSyncMode is the config name for the used SyncMode
const ConfSyncMode = "syncMode"

// ConfSyncAddress is the config name for the remote address used to fetch updated registry files
const ConfSyncAddress = "syncAddress"

// ConfSyncInterval is the config name for the interval in minutes to look for new registry files online
const ConfSyncInterval = "syncInterval"

// ConfOrganisationCertificateValidity is the config name for the number of days organisation certificates are valid
const ConfOrganisationCertificateValidity = "organisationCertificateValidity"

// ConfVendorCACertificateValidity is the config name for the number of days vendor CA certificates are valid
const ConfVendorCACertificateValidity = "vendorCACertificateValidity"

// ConfClientTimeout is the time-out for the client in seconds (e.g. when using the CLI).
const ConfClientTimeout = "clientTimeout"

// ModuleName == VDR
const ModuleName = "VDR"

// Config holds the config for the VDR engine
type Config struct {
	Mode          string
	Datadir       string
	Address       string
	ClientTimeout int
}

// DefaultRegistryConfig returns a fresh Config filled with default values
func DefaultRegistryConfig() Config {
	return Config{
		Datadir:       "./data",
		Address:       "localhost:1323",
		ClientTimeout: 10,
	}
}
