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

	"go.osspkg.com/encrypt/x509cert"
	"go.osspkg.com/goppy/v2/orm"
	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"
	"go.osspkg.com/routine"
	"go.osspkg.com/syncing"

	"go.arwos.org/casper/internal/entity"
)

const (
	updateCrlIntervalSec = 6 * 60 * 60
)

var crlCache = syncing.NewMap[string, []byte](10)

func (v *API) addCrlHandlers() {
	for _, cert := range v.certStore.List() {
		issuer := cert.CA.Cert.Certificate.Issuer.String()

		for _, addr := range cert.CA.Cert.Certificate.CRLDistributionPoints {
			uri, err := url.ParseRequestURI(addr)
			if err != nil {
				logx.Error("Failed to parse crl server URI", "issuer", issuer, "url", addr, "err", err)
				continue
			}

			keyHashB, err := cert.CA.Cert.IssuerKeyHash(entity.Hash)
			if err != nil {
				logx.Error("Failed to get issuer key hash", "issuer", issuer, "err", err)
				continue
			}

			logx.Info("Adding crl server URL", "issuer", issuer, "uri", uri.Path)

			v.crlRoute.Get(uri.Path, func() func(ctx web.Ctx) {
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

func (v *API) autoCleanCrlTicker(ctx context.Context) {
	tik := routine.Ticker{
		Interval: 6 * time.Hour,
		OnStart:  true,
		Calls: []routine.TickFunc{
			func(ctx context.Context, t time.Time) {
				if err := v.entityRepo.DeleteCertExpiredByValidUntil(ctx); err != nil {
					logx.Error("Failed to delete expired certs", "err", err)
				}
			},
		},
	}

	go tik.Run(ctx)
}

func (v *API) updateCrlTicker(ctx context.Context) {
	tik := routine.Ticker{
		Interval: updateCrlIntervalSec * time.Second,
		OnStart:  true,
		Calls: []routine.TickFunc{
			func(ctx context.Context, t time.Time) {

				number := time.Now().UTC().Unix()

				for _, cert := range v.certStore.List() {
					number++

					issuer := cert.CA.Cert.Certificate.Issuer.String()
					logx.Info("Updating CRL", "status", "start", "issuer", issuer)

					keyHashB, err := cert.CA.Cert.IssuerKeyHash(entity.Hash)
					if err != nil {
						logx.Error("Failed to get issuer key hash", "issuer", issuer, "err", err)
						continue
					}

					keyHash := hex.EncodeToString(keyHashB)
					result := make([]x509cert.RevocationEntity, 0, 10)

					err = v.entityRepo.Sync().Query(ctx, "certs_select_revoked", func(q orm.Querier) {
						q.SQL(
							`SELECT "id", "updated_at" FROM "certs" WHERE "issuer_key_hash" = $1 AND "revoked" = true;`,
							keyHash,
						)
						q.Bind(func(bind orm.Scanner) error {
							model := x509cert.RevocationEntity{}
							if e := bind.Scan(&model.SerialNumber, &model.RevocationTime); e != nil {
								return e
							}
							result = append(result, model)
							return nil
						})
					})
					if err != nil {
						logx.Error("Failed to get revoked certs", "issuer", issuer, "err", err)
						continue
					}

					nextUpdate := updateCrlIntervalSec*time.Second + 10*time.Minute
					b, err := x509cert.NewCRL(*cert.CA, number, nextUpdate, result)
					if err != nil {
						logx.Error("Failed to build crl", "issuer", issuer, "err", err)
						continue
					}

					crlCache.Set(keyHash, b.EncodeDER())

					logx.Info("Updating CRL", "status", "done", "issuer", issuer)
				}
			},
		},
	}

	go tik.Run(ctx)
}
