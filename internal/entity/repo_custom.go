/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package entity

import (
	"context"

	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/goppy/v2/orm"
)

const sqlSelectCertNonRevokedByDomain = `
		SELECT ci."id", ci."owner", ci."subject", ci."fingerprint", ci."issuer_key_hash", 
				ci."issuer_name_hash", ci."revoked", ci."revoked_reason", 
				ci."created_at", ci."valid_until", ci."updated_at" 
		FROM "cert_info" ci
		JOIN "cert_domain" cd ON cd."cert_id" = ci."id"
		WHERE cd."domain" = ANY($1) AND ci."revoked" = false;
`

func (v *Repo) SelectCertNonRevokedByDomains(ctx context.Context, domains []string) ([]Cert, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	result := make([]Cert, 0, 2)
	err := v.Sync().Query(ctx, "certs_read_non_revoked_by_domain", func(q orm.Querier) {
		q.SQL(sqlSelectCertNonRevokedByDomain, domains)
		q.Bind(func(bind orm.Scanner) error {
			m := Cert{}
			if e := bind.Scan(&m.SerialNumber, &m.Owner, &m.Subject, &m.FingerPrint,
				&m.IssuerKeyHash, &m.IssuerNameHash, &m.Revoked, &m.RevokedReason,
				&m.CreatedAt, &m.ValidUntil, &m.UpdatedAt); e != nil {
				return e
			}
			result = append(result, m)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

const sqlUpdateCertsAsRevoked = `
			UPDATE "cert_info" 
			SET "revoked" = true, "revoked_reason" = $3, "updated_at" = now()
			WHERE "id" = ANY($1) AND "revoked" = false AND "owner" = $2;
`

func (v *Repo) UpdateCertsAsRevoked(ctx context.Context, ownerId int64, ids []int64, reason int64) error {
	return v.Master().Tx(ctx, "certs_update_as_revoked", func(tx orm.Tx) {
		tx.Exec(func(e orm.Executor) {
			e.SQL(sqlUpdateCertsAsRevoked, ids, ownerId, reason)
		})
	})
}

const sqlDeleteCertExpiredByValidUntil = `DELETE FROM "cert_info" WHERE "valid_until" < now();`

func (v *Repo) DeleteCertExpiredByValidUntil(ctx context.Context) error {
	return v.Master().Tx(ctx, "certs_delete_expired_by_valid_until", func(tx orm.Tx) {
		tx.Exec(func(e orm.Executor) {
			e.SQL(sqlDeleteCertExpiredByValidUntil)
		})
	})
}

const sqlSelectCertRevoked = `
		SELECT "id", "updated_at" 
		FROM "cert_info" 
		WHERE "issuer_key_hash" = $1 AND "revoked" = true AND "valid_until" >= now();
`

func (v *Repo) SelectCertRevoked(ctx context.Context, issuerKeyHash string) ([]pki.RevocationEntity, error) {
	result := make([]pki.RevocationEntity, 0, 2)
	err := v.Sync().Query(ctx, "certs_read_revoked", func(q orm.Querier) {
		q.SQL(sqlSelectCertRevoked, issuerKeyHash)
		q.Bind(func(bind orm.Scanner) error {
			m := pki.RevocationEntity{}
			if e := bind.Scan(&m.SerialNumber, &m.RevocationTime); e != nil {
				return e
			}
			result = append(result, m)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
