/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package cmds

import (
	"context"
	"fmt"
	"strings"

	"go.osspkg.com/console"
	"go.osspkg.com/do"
	"go.osspkg.com/encrypt/pki"
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
			f.String("domains", "Domains for renewal certificate")
			f.StringVar("address", "", "Casper server address")
			f.StringVar("auth-id", "", "Authentication ID")
			f.StringVar("auth-key", "", "Authentication Key")
			f.StringVar("alg", "ecdsa256", "Signature Algorithm")
			f.StringVar("output", fs.CurrentDir(), "Path for save certs")
		})
		setter.ExecFunc(func(_ []string,
			_force bool, _domains string, _address, _authId, _authKey, _alg, _output string,
		) {
			alg, ok := _algorithms[_alg]
			if !ok {
				console.Fatalf("unknown algorithm: %s, can use %s", _alg, strings.Join(do.Keys(_algorithms), ", "))
			}

			domains := do.TreatValue[string](strings.Split(_domains, ","), strings.TrimSpace, strings.ToLower)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go events.OnStopSignal(cancel)

			cli, err := client.New(client.Config{
				Address: _address,
				Proxy:   "env",
				AuthID:  _authId,
				AuthKey: _authKey,
			})
			console.FatalIfErr(err, "init Casper client")

			csr, err := pki.NewCSR(alg, domains...)
			console.FatalIfErr(err, "create CSR")

			out, err := cli.RenewalV1(ctx, _force, *csr.Csr)
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

			caCert := pki.Certificate{}
			newCert := pki.Certificate{Key: csr.Key}

			caCert.Crt, err = pki.UnmarshalCrtPEM([]byte(out.CA))
			console.FatalIfErr(err, "failed to decode CA PEM")

			newCert.Crt, err = pki.UnmarshalCrtPEM([]byte(out.Cert))
			console.FatalIfErr(err, "failed to decode Cert PEM")

			{
				certName := strings.ReplaceAll(domains[0], ".", "_")

				caFileName := fmt.Sprintf("%s/%s.chain.crt", _output, certName)
				console.FatalIfErr(caCert.SaveCert(caFileName), "failed to save CA certificate '%s'", caFileName)

				certFileName := fmt.Sprintf("%s/%s.crt", _output, certName)
				console.FatalIfErr(newCert.SaveCert(certFileName), "failed to save certificate '%s'", certFileName)

				keyFileName := fmt.Sprintf("%s/%s.key", _output, certName)
				console.FatalIfErr(newCert.SaveKey(keyFileName), "failed to save key '%s'", keyFileName)
			}
		})
	})
}
