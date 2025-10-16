/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package client

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"go.osspkg.com/console"
	"go.osspkg.com/do"
	"go.osspkg.com/encrypt/x509cert"
	"go.osspkg.com/ioutils/fs"
)

var algs = map[string]x509.SignatureAlgorithm{
	"rsa256": x509.SHA256WithRSA,
	"rsa384": x509.SHA384WithRSA,
	"rsa512": x509.SHA512WithRSA,
}

func CommandGenerateCA() console.CommandGetter {
	return console.NewCommand(func(setter console.CommandSetter) {
		setter.Setup("ca", "generate Root CA")
		setter.Flag(func(f console.FlagsSetter) {
			f.StringVar("cn", "Root CA L0", "Common Name")
			f.StringVar("org", "Default Organization", "Organization Name")
			f.StringVar("country", "", "Country Name")
			f.StringVar("ocsp", "", "OCSP Server URL")
			f.StringVar("icu", "", "Issuing Certificate URL")
			f.StringVar("crl", "", "CRL Distribution Points")
			f.StringVar("alg", "rsa256", "Signature Algorithm")
			f.IntVar("bits", 2048, "Secret Key bits")
			f.IntVar("deadline", 10*365, "Validity period (in days)")
			f.StringVar("output", fs.CurrentDir(), "Path for save certs")
			f.StringVar("ca-cert", "", "Path for CA certificate for signing")
			f.StringVar("ca-key", "", "Path for CA key for signing")
		})
		setter.ExecFunc(func(_ []string,
			_cn, _org, _country, _ocsp, _icu, _crl, _alg string, _bits, _deadline int64, _output string,
			_caCertPath, _caKeyPath string,
		) {
			alg, ok := algs[_alg]
			if !ok {
				console.Fatalf("unknown algorithm: %s, can use %s", _alg, strings.Join(do.Keys(algs), ", "))
			}

			validityPeriod := time.Duration(_deadline) * time.Hour * 24

			cfg := x509cert.Config{
				Organization:       _org,
				Country:            _country,
				SignatureAlgorithm: alg,
			}
			if _ocsp != "" {
				cfg.OCSPServer = append(cfg.OCSPServer, _ocsp)
			}
			if _icu != "" {
				cfg.IssuingCertificateURL = append(cfg.IssuingCertificateURL, _icu)
			}
			if _crl != "" {
				cfg.CRLDistributionPoints = append(cfg.CRLDistributionPoints, _crl)
			}

			rootCA := x509cert.Cert{
				Cert: &x509cert.RawCert{},
				Key:  &x509cert.RawKey{},
			}
			if _caCertPath != "" && _caKeyPath != "" {
				console.FatalIfErr(rootCA.Cert.DecodePEMFile(_caCertPath), "failed decode CA certificate")
				console.FatalIfErr(rootCA.Key.DecodePEMFile(_caKeyPath), "failed decode CA key")
				if rootCA.IsEmpty() {
					console.Fatalf("CA certificate is empty")
				}
			}

			cert, err := x509cert.NewCA(cfg, &rootCA, int(_bits), validityPeriod, 1, _cn)
			console.FatalIfErr(err, "failed to create CA")

			certFileName := fmt.Sprintf("%s/%s.crt", _output, strings.ToLower(strings.ReplaceAll(_cn, " ", "_")))
			console.FatalIfErr(cert.Cert.EncodePEMFile(certFileName), "failed save CA certificate")
			keyFileName := fmt.Sprintf("%s/%s.key", _output, strings.ToLower(strings.ReplaceAll(_cn, " ", "_")))
			console.FatalIfErr(cert.Key.EncodePEMFile(keyFileName), "failed save CA key")
		})
	})
}
