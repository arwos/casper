/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package entity

import (
	"context"

	"go.osspkg.com/goppy/v2/orm"
)

const sqlSelectCertNonRevokedByDomain = `
		SELECT "id", "owner", "domain", "subject", "fingerprint", "issuer_key_hash", 
				"issuer_name_hash", "revoked", "created_at", "valid_until", "updated_at" 
		FROM "certs" 
		WHERE "domain"=$1 AND "revoked"=false;
`

func (v *Repo) SelectCertNonRevokedByDomain(ctx context.Context, domain string) ([]Cert, error) {
	if len(domain) == 0 {
		return nil, nil
	}
	result := make([]Cert, 0, 2)
	err := v.Sync().Query(ctx, "certs_read_non_revoked_by_domain", func(q orm.Querier) {
		q.SQL(sqlSelectCertNonRevokedByDomain, domain)
		q.Bind(func(bind orm.Scanner) error {
			m := Cert{}
			if e := bind.Scan(&m.SerialNumber, &m.Owner, &m.Domain, &m.Subject, &m.FingerPrint,
				&m.IssuerKeyHash, &m.IssuerNameHash, &m.Revoked,
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
			UPDATE "certs" 
			SET "revoked"=true, "updated_at"=now()
			WHERE "domain"=$1 AND "revoked"=false AND "owner"=$2;
`

func (v *Repo) UpdateCertsAsRevoked(ctx context.Context, ownerId int64, domain string) error {
	return v.Master().Tx(ctx, "certs_update_as_revoked", func(tx orm.Tx) {
		tx.Exec(func(e orm.Executor) {
			e.SQL(sqlUpdateCertsAsRevoked, domain, ownerId)
		})
	})
}

const sqlDeleteCertExpiredByValidUntil = `DELETE FROM "certs" WHERE "valid_until"<now();`

func (v *Repo) DeleteCertExpiredByValidUntil(ctx context.Context) error {
	return v.Master().Tx(ctx, "certs_delete_expired_by_valid_until", func(tx orm.Tx) {
		tx.Exec(func(e orm.Executor) {
			e.SQL(sqlDeleteCertExpiredByValidUntil)
		})
	})
}
