/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package certs

type ConfigGroup struct {
	Certs []Config `yaml:"certs"`
}

type Config struct {
	CACert                   string   `yaml:"cert"`
	CAKey                    string   `yaml:"key"`
	Chain                    []string `yaml:"chain"`
	Domains                  []string `yaml:"domains"`
	DefaultExpireDays        int      `yaml:"default_expire_days"`
	IssuingCertificateURLs   []string `yaml:"issuing_certificate_urls"`
	OCSPServerURLs           []string `yaml:"ocsp_server_urls"`
	CRLDistributionPointURLs []string `yaml:"crl_distribution_point_urls"`
	CertificatePoliciesURLs  []string `yaml:"certificate_policies_urls"`
}

func (c *ConfigGroup) Default() {
	if len(c.Certs) > 0 {
		return
	}

	c.Certs = append(c.Certs,
		Config{
			Chain: []string{
				"/path/to/root-ca-l1.crt",
				"/path/to/root-ca-l0.crt",
			},
			CACert:                   "/path/to/issuing-ca-l2.crt",
			CAKey:                    "/path/to/issuing-ca-l2.key",
			Domains:                  []string{"localhost", "example.com"},
			DefaultExpireDays:        30,
			IssuingCertificateURLs:   []string{"http://pki.domain/icu/ca-l2.crt"},
			OCSPServerURLs:           []string{"http://pki.domain/ocsp/ca-l2"},
			CRLDistributionPointURLs: []string{"http://pki.domain/crl/ca-l2.crl"},
			CertificatePoliciesURLs:  []string{"http://pki.domain/cps/ca-l2.html"},
		},
	)
}
