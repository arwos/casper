/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package certs

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"go.osspkg.com/encrypt/pki"
)

type Certificate struct {
	Chain  map[string]*x509.Certificate
	Issuer *pki.Certificate
	Days   int
	ICUs   []string
	OCSPs  []string
	CRLs   []string
	CPSs   []string
}

func (v *Certificate) GetBySubjectKeyId(ski []byte) (*x509.Certificate, bool) {
	c, ok := v.Chain[hex.EncodeToString(ski)]
	if !ok {
		return nil, false
	}
	return c, true
}

type Store struct {
	domains map[string]*Certificate
	list    []*Certificate
}

func NewStore(c *ConfigGroup) (*Store, error) {
	obj := &Store{
		domains: make(map[string]*Certificate),
		list:    make([]*Certificate, 0, len(c.Certs)),
	}

	for _, conf := range c.Certs {

		cert := &Certificate{
			Chain:  make(map[string]*x509.Certificate),
			Issuer: &pki.Certificate{},
			Days:   conf.DefaultExpireDays,
			ICUs:   conf.IssuingCertificateURLs,
			OCSPs:  conf.OCSPServerURLs,
			CRLs:   conf.CRLDistributionPointURLs,
			CPSs:   conf.CertificatePoliciesURLs,
		}

		for _, path := range conf.RootCaChain {
			ca := &pki.Certificate{}
			if err := ca.LoadCert(path); err != nil {
				return nil, fmt.Errorf("decode root cert %q: %w", path, err)
			}
			if !ca.IsCA() {
				return nil, fmt.Errorf("file %q is not a CA", path)
			}
			cert.Chain[hex.EncodeToString(ca.Crt.SubjectKeyId)] = ca.Crt
		}

		if err := cert.Issuer.LoadCert(conf.IssuingCACert); err != nil {
			return nil, fmt.Errorf("decode cert %q: %w", conf.IssuingCACert, err)
		}
		if err := cert.Issuer.LoadKey(conf.IssuingCAKey); err != nil {
			return nil, fmt.Errorf("decode key %q: %w", conf.IssuingCAKey, err)
		}

		if !cert.Issuer.IsCA() {
			return nil, fmt.Errorf("file %v is not a CA", []string{conf.IssuingCACert, conf.IssuingCAKey})
		}
		if !cert.Issuer.IsValidPair() {
			return nil, fmt.Errorf("file %v is not a valid pair", []string{conf.IssuingCACert, conf.IssuingCAKey})
		}

		obj.list = append(obj.list, cert)
		for _, domain := range conf.Domains {
			obj.domains[domain] = cert
		}
	}

	return obj, nil
}

func (s *Store) GetBySubjectKeyId(domain string, ski []byte) (*x509.Certificate, bool) {
	v, ok := s.domains[domain]
	if !ok {
		return nil, false
	}
	c, ok := v.Chain[hex.EncodeToString(ski)]
	if !ok {
		return nil, false
	}
	return c, true
}

func (s *Store) Get(domain string) (*Certificate, bool) {
	v, ok := s.domains[domain]
	if !ok {
		return nil, false
	}
	return v, true
}

func (s *Store) List() []*Certificate {
	result := make([]*Certificate, 0, len(s.list))
	result = append(result, s.list...)
	return result
}
