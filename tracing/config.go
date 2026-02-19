/*
 * Nuts node
 * Copyright (C) 2026 Nuts community
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

package tracing

// DefaultConfig returns the default configuration for the tracing engine.
func DefaultConfig() Config {
	return Config{}
}

// Config contains settings for OpenTelemetry tracing.
type Config struct {
	// Endpoint is the OTLP collector endpoint for tracing (e.g., "localhost:4318").
	// When empty, tracing is disabled.
	Endpoint string `koanf:"endpoint"`
	// Insecure disables TLS for the OTLP connection.
	Insecure bool `koanf:"insecure"`
	// ServiceName is the service name reported to the tracing backend.
	// Defaults to "nuts-node".
	ServiceName string `koanf:"servicename"`
}
