/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package certs

import (
	"crypto/x509"
	"fmt"
	"time"

	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/ioutils/cache"
	"go.osspkg.com/syncing"
	"go.osspkg.com/xc"
)

type Certificate struct {
	Root *x509.Certificate
	CA   *pki.Certificate
	Days int
	ICUs []string
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
		ca := &pki.Certificate{}
		if err := ca.LoadCert(conf.FileCACert); err != nil {
			return nil, fmt.Errorf("decode cert %q: %w", conf.FileCACert, err)
		}
		if err := ca.LoadKey(conf.FileCAKey); err != nil {
			return nil, fmt.Errorf("decode key %q: %w", conf.FileCAKey, err)
		}

		if !ca.IsCA() {
			return nil, fmt.Errorf("file %v is not a CA", []string{conf.FileCACert, conf.FileCAKey})
		}
		if !ca.IsValidPair() {
			return nil, fmt.Errorf("file %v is not a valid pair", []string{conf.FileCACert, conf.FileCAKey})
		}

		rootCA := &pki.Certificate{}
		if err := rootCA.LoadCert(conf.FileRootCert); err != nil {
			return nil, fmt.Errorf("decode root cert %q: %w", conf.FileRootCert, err)
		}

		if !rootCA.IsCA() {
			return nil, fmt.Errorf("file %v is not a CA", []string{conf.FileRootCert})
		}

		storeItem := &Certificate{
			Root: rootCA.Crt,
			CA:   ca,
			Days: conf.DefaultExpireDays,
			ICUs: conf.IssuingCertificateURLs,
			ttl:  ca.Crt.NotAfter.Unix(),
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
