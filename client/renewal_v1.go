/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package client

//go:generate easyjson

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"go.osspkg.com/encrypt/pki"
)

const PathRenewalV1 = "/api/renewal/v1"

type (
	RenewalStatus string
)

const (
	RenewalStatusActual = "actual"
	RenewalStatusIssued = "issued"
	RenewalStatusFail   = "fail"
)

//easyjson:json
type RenewalModel struct {
	Status RenewalStatus `json:"status"`
	CA     []string      `json:"ca,omitempty"`
	Cert   string        `json:"cert,omitempty"`
}

//easyjson:json
type RenewalRequest struct {
	Force bool   `json:"force"`
	CSR   string `json:"csr"`
}

func (c *_client) RenewalV1(ctx context.Context, force bool, csr x509.CertificateRequest) (*RenewalModel, error) {
	b, err := pki.MarshalCsrPEM(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSR: %w", err)
	}

	req := RenewalRequest{
		Force: force,
		CSR:   string(b),
	}

	resp := &RenewalModel{}
	if err = c.cli.Send(ctx, http.MethodPost, c.cfg.Address+PathRenewalV1, &req, resp); err != nil {
		return nil, fmt.Errorf("failed to renewal: %w", err)
	}

	return resp, nil
}
