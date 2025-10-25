/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"runtime"
	"strings"

	"go.osspkg.com/goppy/v2/auth/signature"
	wc "go.osspkg.com/goppy/v2/web/client"
	"go.osspkg.com/goppy/v2/web/client/comparison"
)

type Client interface {
	RenewalV1(ctx context.Context, force bool, csr x509.CertificateRequest) (*RenewalModel, error)
}

type _client struct {
	cfg *Config
	cli wc.HTTPClient
}

func New(c Config) (Client, error) {
	obj := &_client{
		cfg: &c,
	}

	obj.cfg.Address = strings.TrimRight(c.Address, "/")
	uri, err := url.Parse(obj.cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address %s: %w", obj.cfg.Address, err)
	}

	if len(obj.cfg.AuthID) == 0 {
		return nil, fmt.Errorf("got empty auth id")
	}
	if len(obj.cfg.AuthKey) == 0 {
		return nil, fmt.Errorf("got empty auth key")
	}

	obj.cli = wc.NewHTTPClient(
		wc.WithProxy(c.Proxy),
		wc.WithDefaultHeaders(map[string]string{
			"User-Agent": "casper-client, go_version: " + runtime.Version(),
			"Accept":     "application/json",
		}),
		wc.WithComparisonType(
			comparison.JSON{},
		),
		wc.WithSignatures(map[string]signature.Signature{
			uri.Host: signature.NewSHA1(obj.cfg.AuthID, obj.cfg.AuthKey),
		}),
	)

	return obj, nil
}
