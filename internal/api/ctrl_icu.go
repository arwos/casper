/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package api

import (
	"crypto/x509"
	"net/http"
	"net/url"

	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"
)

func (v *API) addIcuHandlers() {
	for _, cert := range v.certStore.List() {
		for _, addr := range cert.ICUs {
			v.addIcuRoute(addr, cert.Issuer.Crt)

			authCert, ok := cert.GetBySubjectKeyId(cert.Issuer.Crt.AuthorityKeyId)
			if !ok {
				continue
			}

			for _, addr = range authCert.IssuingCertificateURL {
				v.addIcuRoute(addr, authCert)
			}
		}
	}
}

func (v *API) addIcuRoute(addr string, cert *x509.Certificate) {
	issuer := cert.Issuer.String()

	uri, err := url.ParseRequestURI(addr)
	if err != nil {
		logx.Error("Failed to parse issuing server URI", "issuer", issuer, "url", addr, "err", err)
		return
	}

	logx.Info("Adding issuing server URL", "issuer", issuer, "url", uri.Path)

	v.pkiRoute.Get(uri.Path, func() func(ctx web.Ctx) {
		der := pki.MarshalCrtDER(*cert)

		return func(ctx web.Ctx) {
			ctx.Header().Set("Content-Type", "application/pkix-cert")

			ctx.Response().WriteHeader(http.StatusOK)
			if _, err := ctx.Response().Write(der); err != nil {
				logx.Error("Failed to write issuing certificate", "issuer", issuer, "err", err)
			}
		}
	}())
}
