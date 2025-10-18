/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package client

//go:generate easyjson

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.osspkg.com/validate"
)

const PathRenewalV1 = "/api/renewal/v1"

type (
	RenewalStatus string
	RenewalFormat string
)

const (
	RenewalStatusActual = "actual"
	RenewalStatusIssued = "issued"
	RenewalStatusFail   = "fail"

	RenewalFormatPEM = "pem"
	RenewalFormatDER = "der"
)

//easyjson:json
type RenewalModel struct {
	Status RenewalStatus `json:"status"`
	Format RenewalFormat `json:"format"`
	CA     string        `json:"ca,omitempty"`
	Cert   string        `json:"cert,omitempty"`
	Key    string        `json:"key,omitempty"`
}

//easyjson:json
type RenewalRequest struct {
	Force  bool          `json:"force"`
	Domain string        `json:"domain"`
	Format RenewalFormat `json:"format"`
}

func (c *_client) RenewalV1(ctx context.Context, force bool, format RenewalFormat, domain string) (*RenewalModel, error) {
	switch format {
	case RenewalFormatPEM, RenewalFormatDER:
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	if len(domain) == 0 {
		return nil, fmt.Errorf("domain is required")
	}

	if !validate.IsValidDomain(domain) {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	req := RenewalRequest{
		Force:  force,
		Format: format,
		Domain: domain,
	}

	var out []byte

	if err := c.cli.Send(ctx, http.MethodPost, c.cfg.Address+PathRenewalV1, &req, &out); err != nil {
		return nil, fmt.Errorf("failed to renewal: %w", err)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("failed to renewal: no response")
	}

	b, err := c.enc.Decrypt(out)
	if err != nil {
		return nil, fmt.Errorf("failed to renewal decrypt response: %w", err)
	}

	resp := &RenewalModel{}
	if err = json.Unmarshal(b, resp); err != nil {
		return nil, fmt.Errorf("failed to renewal unmarshal response: %w", err)
	}

	return resp, nil
}
