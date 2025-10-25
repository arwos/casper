/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package certs

type ConfigGroup struct {
	Certs []Config `yaml:"certs"`
}

type Config struct {
	FileRootCert           string   `yaml:"root_cert"`
	FileCACert             string   `yaml:"ca_cert"`
	FileCAKey              string   `yaml:"ca_key"`
	Domains                []string `yaml:"domains"`
	DefaultExpireDays      int      `yaml:"default_expire_days"`
	IssuingCertificateURLs []string `yaml:"issuing_certificate_urls"`
}

func (c *ConfigGroup) Default() {
	if len(c.Certs) > 0 {
		return
	}

	c.Certs = append(c.Certs,
		Config{
			Domains:           []string{"localhost"},
			DefaultExpireDays: 30,
		},
		Config{
			Domains:           []string{"example.com"},
			DefaultExpireDays: 90,
		},
	)
}
