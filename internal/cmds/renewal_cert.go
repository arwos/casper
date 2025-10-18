/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package cmds

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"go.osspkg.com/console"
	"go.osspkg.com/encrypt/x509cert"
	"go.osspkg.com/errors"
	"go.osspkg.com/events"
	client2 "go.osspkg.com/goppy/v2/web/client"
	"go.osspkg.com/ioutils/fs"

	"go.arwos.org/casper/client"
)

func RenewalCert() console.CommandGetter {
	return console.NewCommand(func(setter console.CommandSetter) {
		setter.Setup("renewal", "renewal certificate")
		setter.Flag(func(f console.FlagsSetter) {
			f.Bool("force", "Force renewal certificate")
			f.String("domain", "Domain for renewal certificate")
			f.StringVar("address", "", "Casper server address")
			f.StringVar("auth-id", "", "Authentication ID")
			f.StringVar("auth-key", "", "Authentication Key")
			f.StringVar("decrypt-key", "", "Decrypt Key")
			f.StringVar("output", fs.CurrentDir(), "Path for save certs")
		})
		setter.ExecFunc(func(_ []string,
			_force bool, _domain, _address, _authId, _authKey, _decryptKey, _output string,
		) {
			domain := strings.TrimSpace(strings.ToLower(_domain))

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go events.OnStopSignal(cancel)

			cli, err := client.New(client.Config{
				Address:    _address,
				Proxy:      "env",
				AuthID:     _authId,
				AuthKey:    _authKey,
				EncryptKey: _decryptKey,
			})
			console.FatalIfErr(err, "init Casper client")

			out, err := cli.RenewalV1(ctx, _force, client.RenewalFormatPEM, domain)
			if err != nil {
				var httpErr *client2.HTTPError
				if errors.As(err, &httpErr) {
					console.Errorf("response renewal:\n%s", httpErr.Raw.String())
				}
			}

			console.FatalIfErr(err, "failed renewal")

			if out == nil {
				console.Fatalf("no renewal certificate found")
			}

			switch out.Status {
			case client.RenewalStatusActual:
				console.Infof("certificate for the domain is valid")
				return
			case client.RenewalStatusFail:
				console.Errorf("not possible to issue a certificate for domain")
				return
			case client.RenewalStatusIssued:
			}

			caCert := x509cert.Cert{Cert: &x509cert.RawCert{}}
			newCert := x509cert.Cert{Cert: &x509cert.RawCert{}, Key: &x509cert.RawKey{}}

			switch out.Format {
			case client.RenewalFormatPEM:
				console.FatalIfErr(caCert.Cert.DecodePEM([]byte(out.CA)), "failed to decode CA PEM")
				console.FatalIfErr(newCert.Cert.DecodePEM([]byte(out.Cert)), "failed to decode Cert PEM")
				console.FatalIfErr(newCert.Key.DecodePEM([]byte(out.Key)), "failed to decode Key PEM")
			case client.RenewalFormatDER:
				caB, err := base64.StdEncoding.DecodeString(out.CA)
				console.FatalIfErr(err, "failed to decode CA base64")
				console.FatalIfErr(caCert.Cert.DecodeDER(caB), "failed to decode CA DER")
				certB, err := base64.StdEncoding.DecodeString(out.Cert)
				console.FatalIfErr(err, "failed to decode Cert base64")
				console.FatalIfErr(newCert.Cert.DecodeDER(certB), "failed to decode Cert DER")
				keyB, err := base64.StdEncoding.DecodeString(out.Cert)
				console.FatalIfErr(err, "failed to decode Key base64")
				console.FatalIfErr(newCert.Key.DecodeDER(keyB), "failed to decode Key DER")
			default:
				console.Fatalf("got unknown format: %s", out.Format)

			}

			bundle, err := caCert.Cert.EncodePEM()
			console.FatalIfErr(err, "failed to encode CA PEM")
			cb, err := newCert.Cert.EncodePEM()
			console.FatalIfErr(err, "failed to encode Cert PEM")
			bundle = append(bundle, cb...)

			fileName := strings.ReplaceAll(domain, ".", "_")

			certFileName := fmt.Sprintf("%s/%s.bundle.crt", _output, fileName)
			console.FatalIfErr(os.WriteFile(certFileName, bundle, 0644), "failed to save certificate '%s'", certFileName)

			keyFileName := fmt.Sprintf("%s/%s.key", _output, fileName)
			console.FatalIfErr(newCert.Key.EncodePEMFile(keyFileName), "failed to save key '%s'", keyFileName)
		})
	})
}
