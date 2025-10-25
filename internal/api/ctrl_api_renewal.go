/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package api

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.osspkg.com/do"
	"go.osspkg.com/encrypt/pki"
	"go.osspkg.com/errors"
	"go.osspkg.com/goppy/v2/auth/signature"
	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"
	"go.osspkg.com/validate"

	"go.arwos.org/casper/internal/pkgs/certs"

	"go.arwos.org/casper/client"
	"go.arwos.org/casper/internal/entity"
)

var _sigAlg = map[string]crypto.Hash{
	"hmac-sha1":   crypto.SHA1,
	"hmac-sha256": crypto.SHA256,
	"hmac-sha512": crypto.SHA512,
}

var (
	errForbidden      = errors.New("forbidden")
	errInternalError  = errors.New("internal error")
	errInvalidRequest = errors.New("invalid request")
)

func (v *API) addApiHandlers() {
	v.apiRoute.Use(
		web.ThrottlingMiddleware(100),
		v.authzValidate(),
	)
	v.apiRoute.Post(client.PathRenewalV1, v.RenewCertV1)
}

const (
	userRequestCtx       apiCtx = "renew_cert_request"
	userAccessDomainsCtx apiCtx = "user_access_domains"
	ownerIdCtx           apiCtx = "owner_id"
)

func (v *API) authzValidate() web.Middleware {
	return func(next func(web.Ctx)) func(web.Ctx) {
		return func(wc web.Ctx) {
			data, err := signature.Decode(wc.Header())
			if err != nil {
				wc.ErrorJSON(http.StatusForbidden, errForbidden,
					"authorization", "invalid authorization header")
				return
			}

			id, err := uuid.Parse(data.ID)
			if err != nil {
				wc.ErrorJSON(http.StatusForbidden, errForbidden,
					"authorization", "invalid token id", "err", err.Error())
				return
			}

			alg, ok := _sigAlg[data.Alg]
			if !ok {
				wc.ErrorJSON(http.StatusForbidden, errForbidden,
					"authorization", "invalid algorithm", "alg", data.Alg)
				return
			}

			var req []byte
			if err = wc.BindBytes(&req); err != nil {
				wc.ErrorJSON(http.StatusForbidden, errForbidden,
					"authorization", "failed read request", "err", err.Error())
				return
			}

			auth, err := v.entityRepo.SelectAuthByTokenId(wc.Context(), id)
			if err != nil {
				logx.Error("failed to fetch auth by token id", "id", id, "err", err)
				wc.ErrorJSON(http.StatusInternalServerError, errInternalError)
				return
			}

			if len(auth) != 1 || auth[0].TokenId != id || auth[0].Locked || len(auth[0].Domains) == 0 {
				wc.ErrorJSON(http.StatusForbidden, errForbidden,
					"authorization", "account not found", "id", id)
				return
			}

			sig := signature.NewCustomSignature(auth[0].TokenId.String(), auth[0].TokenKey, data.Alg, alg)
			if !sig.Verify(req, data.Sig) {
				wc.ErrorJSON(http.StatusForbidden, errForbidden,
					"authorization", "invalid signature", "id", data.ID, "alg", data.Alg)
				return
			}

			wc.SetContextValue(userRequestCtx, &req)
			wc.SetContextValue(userAccessDomainsCtx, auth[0].Domains)
			wc.SetContextValue(ownerIdCtx, auth[0].ID)

			next(wc)
		}
	}
}

func (v *API) validateCRS(csr *x509.CertificateRequest) error {
	if len(csr.IPAddresses) > 0 {
		return fmt.Errorf("contain IP Addresses")
	}

	if len(csr.DNSNames) == 0 {
		return fmt.Errorf("require DNS Names")
	}

	for _, domain := range csr.DNSNames {
		if !validate.IsValidDomain(domain) {
			return fmt.Errorf("invalid domain: %s", domain)
		}
	}

	return nil
}

func (v *API) getRootCertificate(domains []string) (*certs.Certificate, error) {
	domain := ""
	for _, name := range domains {
		level2 := validate.GetDomainLevel(name, 2)
		if domain == "" {
			domain = level2
		} else if domain != level2 {
			return nil, fmt.Errorf("issuing certificates for different level 2 domains is prohibited")
		}
	}

	if len(domain) == 0 {
		return nil, fmt.Errorf("invalid domain level 2")
	}

	ca, ok := v.certStore.Get(strings.Trim(domain, "."))
	if !ok {
		return nil, fmt.Errorf("not found CA for domain: %s", domain)
	}

	return ca, nil
}

func (v *API) createAndSignCertificate(
	ctx context.Context, ca *certs.Certificate, csr *x509.CertificateRequest, model *entity.Cert,
) (*x509.Certificate, error) {
	if err := v.entityRepo.CreateCert(ctx, model); err != nil {
		return nil, fmt.Errorf("failed to create new certificate: %w", err)
	}

	entityCertDomains := do.Convert[string, *entity.CertDomain](csr.DNSNames,
		func(value string, _ int) *entity.CertDomain {
			return &entity.CertDomain{
				Domain:       value,
				SerialNumber: model.SerialNumber,
			}
		})

	if err := v.entityRepo.CreateBulkCertDomain(ctx, entityCertDomains); err != nil {
		return nil, fmt.Errorf("failed to create domain certificates: %w", err)
	}

	newCert, err := pki.SignCSR(
		pki.Config{IssuingCertificateURLs: ca.ICUs},
		*ca.CA,
		*csr,
		time.Duration(ca.Days)*time.Hour*24,
		model.SerialNumber,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to sign new certificate: %w", err)
	}

	model.Revoked = false
	model.CreatedAt = newCert.NotBefore
	model.ValidUntil = newCert.NotAfter
	model.Subject = newCert.Subject.String()

	fp, err := (&pki.Certificate{Crt: newCert}).FingerPrint(entity.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate fingerprint: %w", err)
	}
	model.FingerPrint = hex.EncodeToString(fp)

	ikh, err := ca.CA.IssuerKeyHash(entity.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate issuer key hash: %w", err)
	}
	model.IssuerKeyHash = hex.EncodeToString(ikh)

	inh, err := ca.CA.IssuerNameHash(entity.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate issuer name hash: %w", err)
	}
	model.IssuerNameHash = hex.EncodeToString(inh)

	if err = v.entityRepo.UpdateCertBySerialNumber(ctx, model); err != nil {
		return nil, fmt.Errorf("failed to update certificate: %w", err)
	}

	return newCert, nil
}

func (v *API) RenewCertV1(wc web.Ctx) {
	ownerId, ok := wc.GetContextValue(ownerIdCtx).(int64)
	if !ok || ownerId <= 0 {
		logx.Error("failed to fetch owner id", "ownerId", ownerId)
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest)
		return
	}

	userDomains, ok := wc.GetContextValue(userAccessDomainsCtx).([]string)
	if !ok || len(userDomains) == 0 {
		logx.Error("failed to fetch user access domains",
			"ownerId", ownerId, "userDomains", userDomains)
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest)
		return
	}

	req, ok := wc.GetContextValue(userRequestCtx).(*[]byte)
	if !ok || req == nil || len(*req) == 0 {
		logx.Error("failed to fetch renew certificate request")
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest)
		return
	}

	renewalRequest := client.RenewalRequest{}
	if err := json.Unmarshal(*req, &renewalRequest); err != nil {
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest,
			"request", "unmarshal request", "err", err.Error())
		return
	}

	csr, err := pki.UnmarshalCsrPEM([]byte(renewalRequest.CSR))
	if err != nil {
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest,
			"request", "unmarshal csr pem", "err", err.Error())
		return
	}

	if err = v.validateCRS(csr); err != nil {
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest,
			"request", "validate", "invalid_csr_attribute", err.Error())
		return
	}

	ca, err := v.getRootCertificate(csr.DNSNames)
	if err != nil {
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest,
			"request", "validate", "err", err.Error())
		return
	}

	exists, err := v.entityRepo.SelectCertNonRevokedByDomains(wc.Context(), csr.DNSNames)
	if err != nil {
		logx.Error("failed to fetch cert non revoked by domains", "domains", csr.DNSNames, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, errInternalError)
		return
	}

	entityModel := entity.Cert{
		Owner:   ownerId,
		Revoked: true,
	}

	resp := client.RenewalModel{
		Status: client.RenewalStatusIssued,
	}

	if len(exists) > 0 {
		for _, exist := range exists {
			if exist.Owner != entityModel.Owner {
				resp.Status = client.RenewalStatusFail
				wc.JSON(http.StatusOK, &resp)
				return
			}

			if !renewalRequest.Force && exist.ValidUntil.After(time.Now().AddDate(0, 0, -3)) {
				resp.Status = client.RenewalStatusActual
				wc.JSON(http.StatusOK, &resp)
				return
			}
		}

		ids := do.Convert[entity.Cert, int64](exists, func(value entity.Cert, _ int) int64 {
			return value.SerialNumber
		})

		if err = v.entityRepo.UpdateCertsAsRevoked(wc.Context(),
			entityModel.Owner, ids, int64(pki.OCSPRevocationReasonSuperseded),
		); err != nil {
			logx.Error("failed to revoke actual certificates", "domains", csr.DNSNames, "err", err)
			wc.ErrorJSON(http.StatusInternalServerError, errInternalError)
			return
		}
	}

	newCert, err := v.createAndSignCertificate(wc.Context(), ca, csr, &entityModel)
	if err != nil {
		logx.Error("failed to create new certificate", "domains", csr.DNSNames, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, errInternalError)
		return
	}

	caPem, err1 := pki.MarshalCrtPEM(*ca.CA.Crt)
	crtPem, err2 := pki.MarshalCrtPEM(*newCert)
	if err1 != nil || err2 != nil {
		wc.ErrorJSON(http.StatusInternalServerError, errors.Wrap(err1, err2))
		return
	}
	resp.CA = string(caPem)
	resp.Cert = string(crtPem)

	wc.JSON(http.StatusOK, &resp)
}
