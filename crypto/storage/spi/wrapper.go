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

package spi

import (
	"context"
	"crypto"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/prometheus/client_golang/prometheus"
	"regexp"
	"time"
)

// wrapper wraps a Storage backend and checks the validity of the kid on each of the relevant functions before
// forwarding the call to the wrapped backend.
type validationWrapper struct {
	kidPattern     *regexp.Regexp
	wrappedBackend Storage
}

func (w validationWrapper) Name() string {
	return w.wrappedBackend.Name()
}

func (w validationWrapper) CheckHealth() map[string]core.Health {
	return w.wrappedBackend.CheckHealth()
}

// NewValidatedKIDBackendWrapper creates a new wrapper for storage backends.
// Every call to the backend which takes a kid as param, gets the kid validated against the provided kidPattern.
func NewValidatedKIDBackendWrapper(backend Storage, kidPattern *regexp.Regexp) Storage {
	return validationWrapper{
		kidPattern:     kidPattern,
		wrappedBackend: backend,
	}
}

func (w validationWrapper) validateKID(kid string) error {
	if !w.kidPattern.MatchString(kid) {
		return fmt.Errorf("invalid key ID: %s", kid)
	}
	return nil
}

func (w validationWrapper) GetPrivateKey(ctx context.Context, keyName string, version string) (crypto.Signer, error) {
	if err := w.validateKID(keyName); err != nil {
		return nil, err
	}
	return w.wrappedBackend.GetPrivateKey(ctx, keyName, version)
}

func (w validationWrapper) PrivateKeyExists(ctx context.Context, keyName string, version string) (bool, error) {
	if err := w.validateKID(keyName); err != nil {
		return false, err
	}
	return w.wrappedBackend.PrivateKeyExists(ctx, keyName, version)
}

func (w validationWrapper) SavePrivateKey(ctx context.Context, kid string, key crypto.PrivateKey) error {
	if err := w.validateKID(kid); err != nil {
		return err
	}
	return w.wrappedBackend.SavePrivateKey(ctx, kid, key)
}

func (w validationWrapper) DeletePrivateKey(ctx context.Context, keyName string) error {
	if err := w.validateKID(keyName); err != nil {
		return err
	}
	return w.wrappedBackend.DeletePrivateKey(ctx, keyName)
}

func (w validationWrapper) ListPrivateKeys(ctx context.Context) []KeyNameVersion {
	return w.wrappedBackend.ListPrivateKeys(ctx)
}

func (w validationWrapper) NewPrivateKey(ctx context.Context, keyName string) (crypto.PublicKey, string, error) {
	publicKey, version, err := w.wrappedBackend.NewPrivateKey(ctx, keyName)
	if err != nil {
		return nil, "", err
	}
	return publicKey, version, err
}

func NewPrometheusWrapper(backend Storage) *PrometheusWrapper {
	return &PrometheusWrapper{
		wrappedBackend: backend,
		opDurationMetric: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "crypto_storage_op_duration_seconds",
			Help:    "Duration of crypto storage operations in seconds (experimental, may be removed without notice)",
			Buckets: []float64{0.01, 0.05, 0.1, .5, 1, 2},
		}, []string{"op"}),
	}
}

var _ Storage = (*PrometheusWrapper)(nil)

type PrometheusWrapper struct {
	wrappedBackend   Storage
	opDurationMetric *prometheus.HistogramVec
}

func (p PrometheusWrapper) Collectors() []prometheus.Collector {
	return []prometheus.Collector{p.opDurationMetric}
}

func (p PrometheusWrapper) Name() string {
	return p.wrappedBackend.Name()
}

func (p PrometheusWrapper) CheckHealth() map[string]core.Health {
	return p.wrappedBackend.CheckHealth()
}

func (p PrometheusWrapper) NewPrivateKey(ctx context.Context, keyName string) (crypto.PublicKey, string, error) {
	start := time.Now()
	defer func() {
		p.opDurationMetric.WithLabelValues("new_private_key").Observe(time.Since(start).Seconds())
	}()
	return p.wrappedBackend.NewPrivateKey(ctx, keyName)
}

func (p PrometheusWrapper) GetPrivateKey(ctx context.Context, keyName string, version string) (crypto.Signer, error) {
	start := time.Now()
	defer func() {
		p.opDurationMetric.WithLabelValues("get_private_key").Observe(time.Since(start).Seconds())
	}()
	return p.wrappedBackend.GetPrivateKey(ctx, keyName, version)
}

func (p PrometheusWrapper) PrivateKeyExists(ctx context.Context, keyName string, version string) (bool, error) {
	start := time.Now()
	defer func() {
		p.opDurationMetric.WithLabelValues("private_key_exists").Observe(time.Since(start).Seconds())
	}()
	return p.wrappedBackend.PrivateKeyExists(ctx, keyName, version)
}

func (p PrometheusWrapper) SavePrivateKey(ctx context.Context, keyname string, key crypto.PrivateKey) error {
	start := time.Now()
	defer func() {
		p.opDurationMetric.WithLabelValues("save_private_key").Observe(time.Since(start).Seconds())
	}()
	return p.wrappedBackend.SavePrivateKey(ctx, keyname, key)
}

func (p PrometheusWrapper) ListPrivateKeys(ctx context.Context) []KeyNameVersion {
	start := time.Now()
	defer func() {
		p.opDurationMetric.WithLabelValues("list_private_keys").Observe(time.Since(start).Seconds())
	}()
	return p.wrappedBackend.ListPrivateKeys(ctx)
}

func (p PrometheusWrapper) DeletePrivateKey(ctx context.Context, keyName string) error {
	start := time.Now()
	defer func() {
		p.opDurationMetric.WithLabelValues("delete_private_key").Observe(time.Since(start).Seconds())
	}()
	return p.wrappedBackend.DeletePrivateKey(ctx, keyName)
}
