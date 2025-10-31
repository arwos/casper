/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package cmds

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.osspkg.com/console"
	"go.osspkg.com/do"
	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/errors"
	"go.osspkg.com/events"
	web "go.osspkg.com/goppy/v2/web/client"
	"go.osspkg.com/ioutils/codec"
	"go.osspkg.com/ioutils/fs"
	"go.osspkg.com/routine"

	"go.arwos.org/casper/client"
)

func errWrap(err error, domain string) {
	if err == nil {
		return
	}
	fmt.Println("[ERROR]", err.Error(), "(domains: ", domain, ")")
}

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
			f.StringVar("filename", "cert", "Filename for save certs")
		})
		setter.ExecFunc(func(_ []string,
			_force bool, _domains string, _address, _authId, _authKey, _alg, _output, _filename string,
		) {

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go events.OnStopSignal(cancel)

			errWrap(
				renewalCertificate(ctx, _force, _domains, _address, _authId, _authKey, _alg, _output, _filename),
				_domains,
			)
		})
	})
}

type (
	AutoConfig struct {
		ApiHost   string        `yaml:"api_address"`
		Interval  time.Duration `yaml:"interval"`
		StorePath string        `yaml:"store_path"`
		AuthID    string        `yaml:"auth_id"`
		AuthToken string        `yaml:"auth_token"`
		Algorithm string        `yaml:"algorithm"`
		Requests  []AutoRequest `yaml:"requests"`
	}
	AutoRequest struct {
		Domains  []string `yaml:"domains"`
		Filename string   `yaml:"filename"`
	}
)

func RenewalCertAuto() console.CommandGetter {
	return console.NewCommand(func(setter console.CommandSetter) {
		setter.Setup("auto", "auto renewal certificate")
		setter.Flag(func(f console.FlagsSetter) {
			f.String("config", "Config for autorenewal certificate")
		})
		setter.ExecFunc(func(_ []string, filepath string) {
			cfg := AutoConfig{}
			console.FatalIfErr((codec.FileEncoder(filepath)).Decode(&cfg), "decode config")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go events.OnStopSignal(cancel)

			tik := &routine.Ticker{
				Interval: cfg.Interval,
				OnStart:  true,
				Calls: []routine.TickFunc{
					func(ctx context.Context, _ time.Time) {
						for _, request := range cfg.Requests {
							domains := strings.Join(request.Domains, ",")
							errWrap(
								renewalCertificate(ctx, false, domains,
									cfg.ApiHost, cfg.AuthID, cfg.AuthToken,
									cfg.Algorithm, cfg.StorePath, request.Filename),
								domains,
							)
						}
					},
				},
			}
			tik.Run(ctx)
		})
	})
}

func renewalCertificate(
	ctx context.Context, _force bool, _domains string, _address, _authId, _authKey, _alg, _output, _filename string,
) error {
	alg, ok := _algorithms[_alg]
	if !ok {
		return fmt.Errorf("unknown algorithm: %s, can use %s", _alg, strings.Join(do.Keys(_algorithms), ", "))
	}

	domains := do.TreatValue[string](strings.Split(_domains, ","), strings.TrimSpace, strings.ToLower)

	cli, err := client.New(client.Config{
		Address: _address,
		Proxy:   "env",
		AuthID:  _authId,
		AuthKey: _authKey,
	})
	if err != nil {
		return errors.Wrapf(err, "init Casper client")
	}

	csr, err := pki.NewCSR(alg, domains...)
	if err != nil {
		return errors.Wrapf(err, "create CSR")
	}

	out, err := cli.RenewalV1(ctx, _force, *csr.Csr)
	if err != nil {
		var httpErr *web.HTTPError
		if errors.As(err, &httpErr) {
			console.Errorf("response renewal:\n%s", httpErr.Raw.String())
		}
		return errors.Wrapf(err, "failed renewal")
	}

	if out == nil {
		return fmt.Errorf("no renewal certificate found")
	}

	switch out.Status {
	case client.RenewalStatusActual:
		return fmt.Errorf("certificate for the domain is valid")
	case client.RenewalStatusFail:
		return fmt.Errorf("not possible to issue a certificate for domain")
	case client.RenewalStatusIssued:
	}

	caCert := pki.Certificate{}
	newCert := pki.Certificate{Key: csr.Key}

	caCert.Crt, err = pki.UnmarshalCrtPEM([]byte(out.CA))
	if err != nil {
		return errors.Wrapf(err, "failed to decode CA PEM")
	}

	newCert.Crt, err = pki.UnmarshalCrtPEM([]byte(out.Cert))
	if err != nil {
		return errors.Wrapf(err, "failed to decode Cert PEM")
	}

	{
		certName := strings.ToLower(strings.TrimSpace(_filename))

		caFileName := fmt.Sprintf("%s/%s.chain.crt", _output, certName)
		certFileName := fmt.Sprintf("%s/%s.crt", _output, certName)
		keyFileName := fmt.Sprintf("%s/%s.key", _output, certName)

		if err = caCert.SaveCert(caFileName); err != nil {
			return errors.Wrapf(err, "failed to save CA certificate '%s'", caFileName)
		}
		if err = setLinuxAccess(_output, certName+".chain"); err != nil {
			return err
		}
		if err = newCert.SaveCert(certFileName); err != nil {
			return errors.Wrapf(err, "failed to save certificate '%s'", certFileName)
		}
		if err = newCert.SaveKey(keyFileName); err != nil {
			return errors.Wrapf(err, "failed to save key '%s'", keyFileName)
		}
		if err = setLinuxAccess(_output, certName); err != nil {
			return err
		}
	}

	return nil
}
