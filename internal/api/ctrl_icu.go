/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package api

import (
	"net/http"
	"net/url"

	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"
)

func (v *API) addIcuHandlers() {
	for _, cert := range v.certStore.List() {
		issuer := cert.Issuer.Crt.Issuer.String()

		for _, addr := range cert.Issuer.Crt.IssuingCertificateURL {
			uri, err := url.ParseRequestURI(addr)
			if err != nil {
				logx.Error("Failed to parse issuing server URI", "issuer", issuer, "url", addr, "err", err)
				continue
			}

			logx.Info("Adding issuing server URL", "issuer", issuer, "url", uri.Path)

			v.pkiRoute.Get(uri.Path, func() func(ctx web.Ctx) {
				der := pki.MarshalCrtDER(*cert.Issuer.Crt)
				issuer := issuer

				return func(ctx web.Ctx) {
					ctx.Header().Set("Content-Type", "application/pkix-cert")
					ctx.Header().Set("Cache-Control", "max-age=86400,s-maxage=14400,public,no-transform,must-revalidate")
					ctx.Response().WriteHeader(http.StatusOK)
					if _, err := ctx.Response().Write(der); err != nil {
						logx.Error("Failed to write issuing certificate", "issuer", issuer, "err", err)
					}
				}
			}())
		}
	}
}
