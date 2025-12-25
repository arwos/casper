/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"
	"go.osspkg.com/routine/tick"
	"go.osspkg.com/syncing"

	"go.arwos.org/casper/internal/entity"
)

const (
	updateCrlIntervalSec = 6 * 60 * 60
)

var crlCache = syncing.NewMap[string, []byte](10)

func (v *API) addCrlHandlers() {
	for _, cert := range v.certStore.List() {
		issuer := cert.Issuer.Crt.Issuer.String()

		for _, addr := range cert.Issuer.Crt.CRLDistributionPoints {
			uri, err := url.ParseRequestURI(addr)
			if err != nil {
				logx.Error("Failed to parse crl server URI", "issuer", issuer, "url", addr, "err", err)
				continue
			}

			keyHashB, err := cert.Issuer.IssuerKeyHash(entity.Hash)
			if err != nil {
				logx.Error("Failed to get issuer key hash", "issuer", issuer, "err", err)
				continue
			}

			logx.Info("Adding crl server URL", "issuer", issuer, "uri", uri.Path)

			v.pkiRoute.Get(uri.Path, func() func(ctx web.Ctx) {
				keyHash := hex.EncodeToString(keyHashB)
				cc := fmt.Sprintf("max-age=%d,s-maxage=14400,public,no-transform,must-revalidate", updateCrlIntervalSec)

				return func(ctx web.Ctx) {
					ctx.Header().Set("Content-Type", "application/pkix-crl")
					ctx.Header().Set("Cache-Control", cc)

					b, ok := crlCache.Get(keyHash)
					if !ok {
						ctx.Error(http.StatusInternalServerError, nil)
						return
					}

					ctx.Response().WriteHeader(http.StatusOK)
					if _, err := ctx.Response().Write(b); err != nil {
						logx.Error("Failed to write crl", "issuer", issuer, "err", err)
					}
				}
			}())
		}
	}
}

func (v *API) tickerConfigCleanCrl() tick.Config {
	return tick.Config{
		Name:     "delete expired certs",
		OnStart:  true,
		Interval: 6 * time.Hour,
		Func: func(ctx context.Context, _ time.Time) error {
			return v.entityRepo.DeleteCertExpiredByValidUntil(ctx)
		},
	}
}

func (v *API) tickerConfigBuildCrl() tick.Config {
	return tick.Config{
		Name:     "build revoked certs list",
		OnStart:  true,
		Interval: updateCrlIntervalSec * time.Second,
		Func: func(ctx context.Context, t time.Time) error {
			number := t.UTC().Unix()

			for _, cert := range v.certStore.List() {
				number++

				issuer := cert.Issuer.Crt.Issuer.String()
				logx.Info("Updating CRL", "status", "start", "issuer", issuer)

				keyHashB, err := cert.Issuer.IssuerKeyHash(entity.Hash)
				if err != nil {
					logx.Error("Failed to get issuer key hash", "issuer", issuer, "err", err)
					continue
				}

				keyHash := hex.EncodeToString(keyHashB)

				result, err := v.entityRepo.SelectCertRevoked(ctx, keyHash)
				if err != nil {
					logx.Error("Failed to get revoked certs", "issuer", issuer, "err", err)
					continue
				}

				nextUpdate := updateCrlIntervalSec*time.Second + 10*time.Minute
				b, err := pki.NewCRL(*cert.Issuer, number, nextUpdate, result)
				if err != nil {
					logx.Error("Failed to build crl", "issuer", issuer, "err", err)
					continue
				}

				crlCache.Set(keyHash, b)

				logx.Info("Updating CRL", "status", "done", "issuer", issuer)
			}

			return nil
		},
	}
}
