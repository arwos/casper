/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package entity

import (
	"crypto"
	"time"
)

var Hash = crypto.SHA1

//gen:orm table=auth
type Auth struct {
	ID         int64     // col=id index=pk
	Token      string    // col=token len=128
	EncryptKey string    // col=enc_key len=45
	Domains    []string  // col=domains
	Locked     bool      // col=locked
	CreatedAt  time.Time // col=created_at auto=c:time.Now()
	UpdatedAt  time.Time // col=updated_at auto=u:time.Now()
}

//gen:orm table=certs
type Cert struct {
	SerialNumber   int64     // col=id index=pk
	Owner          int64     // col=owner index=fk:auth.id
	Domain         string    // col=domain len=254 index=idx
	Subject        string    // col=subject
	FingerPrint    string    // col=fingerprint
	IssuerKeyHash  string    // col=issuer_key_hash index=idx
	IssuerNameHash string    // col=issuer_name_hash
	Revoked        bool      // col=revoked
	CreatedAt      time.Time // col=created_at
	ValidUntil     time.Time // col=valid_until
	UpdatedAt      time.Time // col=updated_at auto=u:time.Now()
}
