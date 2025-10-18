/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	"go.osspkg.com/encrypt/x509cert"
	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"
	"golang.org/x/crypto/ocsp"

	"go.arwos.org/casper/internal/entity"
)

func (v *API) addOCSPHandlers() {
	for _, cert := range v.certStore.List() {
		issuer := cert.CA.Cert.Certificate.Issuer.String()

		srv := &x509cert.OCSPServer{
			CA: *cert.CA,
			Resolver: &ocspStatusResolve{
				repo:   v.entityRepo,
				cert:   cert.CA,
				issuer: issuer,
			},
			UpdateInterval: 60 * time.Minute,
		}

		for _, addr := range cert.CA.Cert.Certificate.OCSPServer {
			uri, err := url.ParseRequestURI(addr)
			if err != nil {
				logx.Error("Failed to parse OCSP server URI", "issuer", issuer, "url", addr, "err", err)
				continue
			}

			logx.Info("Adding OCSP server URL", "issuer", issuer, "url", uri.Path)

			v.ocspRoute.Post(uri.Path, func(ctx web.Ctx) {
				srv.HTTPHandler(ctx.Response(), ctx.Request())
			})
		}
	}
}

type ocspStatusResolve struct {
	repo   *entity.Repo
	cert   *x509cert.Cert
	issuer string
}

func (v *ocspStatusResolve) OCSPStatusResolve(ctx context.Context, r *ocsp.Request) (x509cert.OCSPStatus, error) {
	id := r.SerialNumber.Int64()
	data, err := v.repo.SelectCertBySerialNumber(ctx, id)
	if err != nil {
		logx.Error("Failed to select OCSP status", "id", id, "err", err)
		return ocsp.ServerFailed, fmt.Errorf("internal error")
	}

	if len(data) == 0 {
		return x509cert.OCSPStatusUnknown, nil
	}

	{
		caVal, caErr := v.cert.Cert.IssuerKeyHash(entity.Hash)
		reqVal, reqErr := v.cert.Cert.IssuerKeyHash(r.HashAlgorithm)

		if caErr != nil || reqErr != nil {
			logx.Error("Failed to get issuer key hash", "issuer", v.issuer, "err", errors.Join(caErr, reqErr))
			return ocsp.ServerFailed, fmt.Errorf("internal error")
		}

		caHex := hex.EncodeToString(caVal)

		if data[0].IssuerKeyHash != caHex || caHex != hex.EncodeToString(reqVal) {
			return x509cert.OCSPStatusUnknown, nil
		}
	}

	{
		caVal, caErr := v.cert.Cert.IssuerNameHash(entity.Hash)
		reqVal, reqErr := v.cert.Cert.IssuerNameHash(r.HashAlgorithm)

		if caErr != nil || reqErr != nil {
			logx.Error("Failed to get issuer name hash", "issuer", v.issuer, "err", errors.Join(caErr, reqErr))
			return ocsp.ServerFailed, fmt.Errorf("internal error")
		}

		caHex := hex.EncodeToString(caVal)

		if data[0].IssuerNameHash != caHex || caHex != hex.EncodeToString(reqVal) {
			return x509cert.OCSPStatusUnknown, nil
		}
	}

	if data[0].Revoked {
		return x509cert.OCSPStatusRevoked, nil
	}

	return x509cert.OCSPStatusGood, nil
}
