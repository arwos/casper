/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package cmds

import (
	"fmt"
	"strings"
	"time"

	"go.osspkg.com/console"
	"go.osspkg.com/do"
	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/ioutils/fs"
)

func GenerateCA() console.CommandGetter {
	return console.NewCommand(func(setter console.CommandSetter) {
		setter.Setup("ca", "generate Root CA")
		setter.Flag(func(f console.FlagsSetter) {
			f.StringVar("cn", "Root CA L0", "Common Name")
			f.StringVar("org", "Default Organization", "Organization Name")
			f.StringVar("country", "", "Country Name")
			f.StringVar("ocsp", "", "OCSP Server URL")
			f.StringVar("cps", "", "Certificate Policies URL")
			f.StringVar("icu", "", "Issuing Certificate URL")
			f.StringVar("crl", "", "CRL Distribution Points")
			f.StringVar("alg", "ecdsa256", "Signature Algorithm")
			f.StringVar("email", "", "Casper PKI Email Address")
			f.IntVar("deadline", 10*365, "Validity period (in days)")
			f.StringVar("output", fs.CurrentDir(), "Path for save certs")
			f.StringVar("ca-cert", "", "Path for CA certificate for signing")
			f.StringVar("ca-key", "", "Path for CA key for signing")
		})
		setter.ExecFunc(func(_ []string,
			_cn, _org, _country, _ocsp, _cps, _icu, _crl, _alg, _email string, _deadline int64, _output string,
			_caCertPath, _caKeyPath string,
		) {
			alg, ok := _algorithms[_alg]
			if !ok {
				console.Fatalf("unknown algorithm: %s, can use %s", _alg, strings.Join(do.Keys(_algorithms), ", "))
			}

			validityPeriod := time.Duration(_deadline) * time.Hour * 24

			cfg := pki.Config{
				SignatureAlgorithm: alg,
				Organization:       strings.TrimSpace(_org),
				Country:            strings.TrimSpace(_country),
				CommonName:         strings.TrimSpace(_cn),
			}
			cfg.OCSPServerURLs = append(cfg.OCSPServerURLs, _ocsp)
			cfg.IssuingCertificateURLs = append(cfg.IssuingCertificateURLs, _icu)
			cfg.CRLDistributionPointURLs = append(cfg.CRLDistributionPointURLs, _crl)
			cfg.CertificatePoliciesURLs = append(cfg.CertificatePoliciesURLs, _cps)
			cfg.EmailAddress = append(cfg.EmailAddress, _email)

			rootCA := pki.Certificate{}
			if _caCertPath != "" && _caKeyPath != "" {
				console.FatalIfErr(rootCA.LoadCert(_caCertPath), "failed decode CA certificate")
				console.FatalIfErr(rootCA.LoadKey(_caKeyPath), "failed decode CA private key")
				if !rootCA.IsValidPair() {
					console.Fatalf("invalid CA certificate")
				}
			}

			var (
				err  error
				cert *pki.Certificate
			)
			if !rootCA.IsValidPair() {
				cert, err = pki.NewCA(cfg, validityPeriod, time.Now().Unix(), true)
			} else {
				cert, err = pki.NewIntermediateCA(cfg, rootCA, validityPeriod, time.Now().Unix())
			}
			console.FatalIfErr(err, "failed to create CA")

			certName := strings.ToLower(strings.ReplaceAll(_cn, " ", "_"))
			console.FatalIfErr(
				cert.SaveCert(fmt.Sprintf("%s/%s.crt", _output, certName)),
				"failed save CA certificate")
			console.FatalIfErr(
				cert.SaveKey(fmt.Sprintf("%s/%s.key", _output, certName)),
				"failed save CA private key")
		})
	})
}
