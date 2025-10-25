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

	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"

	"go.arwos.org/casper/internal/entity"
)

func (v *API) addOCSPHandlers() {
	for _, cert := range v.certStore.List() {
		issuer := cert.CA.Crt.Issuer.String()

		srv := &pki.OCSPServer{
			CA: *cert.CA,
			Resolver: &ocspStatusResolve{
				repo:   v.entityRepo,
				cert:   *cert.CA,
				issuer: issuer,
			},
			UpdateInterval: 59 * time.Minute,
			OnError: func(err error) {
				logx.Error("Failed OCSP server request", "issuer", issuer, "err", err)
			},
		}

		for _, addr := range cert.CA.Crt.OCSPServer {
			uri, err := url.ParseRequestURI(addr)
			if err != nil {
				logx.Error("Failed to parse OCSP server URI", "issuer", issuer, "url", addr, "err", err)
				continue
			}

			logx.Info("Adding OCSP server URL", "issuer", issuer, "url", uri.Path)

			v.pkiRoute.Post(uri.Path, func(ctx web.Ctx) {
				srv.HTTPHandler(ctx.Response(), ctx.Request())
			})
		}
	}
}

type ocspStatusResolve struct {
	repo   *entity.Repo
	cert   pki.Certificate
	issuer string
}

func (v *ocspStatusResolve) OCSPStatusResolve(ctx context.Context, r *pki.OCSPRequest) (*pki.OCSPResponse, error) {
	id := r.SerialNumber.Int64()

	data, err := v.repo.SelectCertBySerialNumber(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch status (%d): %w", id, err)
	}

	if len(data) == 0 {
		return &pki.OCSPResponse{Status: pki.OCSPStatusUnknown}, nil
	}

	{
		dbVal, caErr := v.cert.IssuerKeyHash(entity.Hash)
		reqVal, reqErr := v.cert.IssuerKeyHash(r.HashAlgorithm)

		if caErr != nil || reqErr != nil {
			return nil, fmt.Errorf("failed create issuer key hash (%d): %w", id, err)
		}

		if data[0].IssuerKeyHash != hex.EncodeToString(dbVal) ||
			hex.EncodeToString(r.IssuerKeyHash) != hex.EncodeToString(reqVal) {
			return &pki.OCSPResponse{Status: pki.OCSPStatusUnknown}, nil
		}
	}

	{
		dbVal, caErr := v.cert.IssuerNameHash(entity.Hash)
		reqVal, reqErr := v.cert.IssuerNameHash(r.HashAlgorithm)

		if caErr != nil || reqErr != nil {
			logx.Error("Failed to get issuer name hash", "issuer", v.issuer, "err", errors.Join(caErr, reqErr))
			return nil, fmt.Errorf("failed create issuer name hash (%d): %w", id, err)
		}

		if data[0].IssuerNameHash != hex.EncodeToString(dbVal) ||
			hex.EncodeToString(r.IssuerNameHash) != hex.EncodeToString(reqVal) {
			return &pki.OCSPResponse{Status: pki.OCSPStatusUnknown}, nil
		}
	}

	if data[0].Revoked {
		return &pki.OCSPResponse{
			Status:           pki.OCSPStatusRevoked,
			RevokedAt:        data[0].UpdatedAt,
			RevocationReason: pki.OCSPRevocationReason(data[0].RevokedReason),
		}, nil
	}

	return &pki.OCSPResponse{Status: pki.OCSPStatusGood}, nil
}
