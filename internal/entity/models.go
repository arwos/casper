/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package entity

import (
	"crypto"
	"time"

	"github.com/google/uuid"
)

var Hash = crypto.SHA1

//gen:orm table=auth
type Auth struct {
	ID        int64     // col=id index=pk
	TokenId   uuid.UUID // col=token_id index=unq
	TokenKey  string    // col=token_key len=128
	Domains   []string  // col=domains
	Locked    bool      // col=locked
	CreatedAt time.Time // col=created_at auto=c:time.Now()
	UpdatedAt time.Time // col=updated_at auto=u:time.Now()
}

//gen:orm table=cert_info
type Cert struct {
	SerialNumber   int64     // col=id index=pk
	Owner          int64     // col=owner index=fk:auth.id
	Subject        string    // col=subject
	FingerPrint    string    // col=fingerprint
	IssuerKeyHash  string    // col=issuer_key_hash index=idx
	IssuerNameHash string    // col=issuer_name_hash
	Revoked        bool      // col=revoked
	RevokedReason  int64     // col=revoked_reason
	CreatedAt      time.Time // col=created_at
	ValidUntil     time.Time // col=valid_until
	UpdatedAt      time.Time // col=updated_at auto=u:time.Now()
}

//gen:orm table=cert_domain
type CertDomain struct {
	SerialNumber int64  // col=cert_id index=fk:cert_info.id
	Domain       string // col=domain index=idx
}
