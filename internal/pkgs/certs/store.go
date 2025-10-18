/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package certs

import (
	"fmt"
	"time"

	"go.osspkg.com/encrypt/x509cert"
	"go.osspkg.com/ioutils/cache"
	"go.osspkg.com/syncing"
	"go.osspkg.com/xc"
)

type Certificate struct {
	Root *x509cert.Cert
	CA   *x509cert.Cert
	Days int
	Icu  string
	ttl  int64
}

func (i *Certificate) Timestamp() int64 {
	return i.ttl
}

type Store struct {
	cache cache.Cache[string, *Certificate]
	list  syncing.Slice[*Certificate]
}

func NewStore(ctx xc.Context, c *ConfigGroup) (*Store, error) {
	obj := &Store{
		cache: cache.New[string, *Certificate](
			cache.OptTimeClean[string, *Certificate](ctx.Context(), 15*time.Minute),
		),
	}

	for _, conf := range c.Certs {
		ca := &x509cert.Cert{
			Cert: &x509cert.RawCert{},
			Key:  &x509cert.RawKey{},
		}
		if err := ca.Cert.DecodePEMFile(conf.FileCACert); err != nil {
			return nil, fmt.Errorf("decode cert %q: %w", conf.FileCACert, err)
		}
		if err := ca.Key.DecodePEMFile(conf.FileCAKey); err != nil {
			return nil, fmt.Errorf("decode key %q: %w", conf.FileCAKey, err)
		}

		rootCA := &x509cert.Cert{
			Cert: &x509cert.RawCert{},
		}
		if err := rootCA.Cert.DecodePEMFile(conf.FileRootCert); err != nil {
			return nil, fmt.Errorf("decode root cert %q: %w", conf.FileRootCert, err)
		}

		storeItem := &Certificate{
			Root: rootCA,
			CA:   ca,
			Days: conf.DefaultExpireDays,
			ttl:  ca.Cert.Certificate.NotAfter.Unix(),
			Icu:  conf.IssuingCertificateURL,
		}

		obj.list.Append(storeItem)
		for _, domain := range conf.Domains {
			obj.cache.Set(domain, storeItem)
		}
	}

	return obj, nil
}

func (s *Store) Get(name string) (*Certificate, bool) {
	v, ok := s.cache.Get(name)
	if !ok {
		return nil, false
	}
	return v, true
}

func (s *Store) List() []*Certificate {
	result := make([]*Certificate, 0, s.list.Size())

	for cert := range s.list.Yield() {
		result = append(result, cert)
	}

	return result
}
