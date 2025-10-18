/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package api

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.osspkg.com/encrypt/aesgcm"
	"go.osspkg.com/encrypt/x509cert"
	"go.osspkg.com/errors"
	"go.osspkg.com/goppy/v2/auth/signature"
	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"
	"go.osspkg.com/validate"

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
	errInvalidRequest = errors.New("invalid request")
	errInvalidAuthAlg = errors.New("invalid auth algorithm")
)

func (v *API) addApiHandlers() {
	v.apiRoute.Use(web.ThrottlingMiddleware(100))
	v.apiRoute.Post(client.PathRenewalV1, v.RenewCert)
}

//nolint:gocyclo
func (v *API) RenewCert(wc web.Ctx) {
	sigData, err := signature.Decode(wc.Header())
	if err != nil {
		wc.ErrorJSON(http.StatusForbidden, errForbidden)
		return
	}

	sigAlg, ok := _sigAlg[sigData.Alg]
	if !ok {
		wc.ErrorJSON(http.StatusBadRequest, errInvalidAuthAlg)
		return
	}

	id, err := strconv.ParseInt(sigData.ID, 10, 64)
	if err != nil {
		logx.Warn("failed to parse api id", "id", sigData.ID, "err", err)
		wc.ErrorJSON(http.StatusForbidden, err)
		return
	}

	var req []byte
	if err = wc.BindBytes(&req); err != nil {
		logx.Warn("failed to bind request", "id", sigData.ID, "err", err)
		wc.ErrorJSON(http.StatusBadRequest, err)
		return
	}

	model := client.RenewalRequest{}
	if err = json.Unmarshal(req, &model); err != nil {
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	model.Domain = strings.TrimSpace(strings.ToLower(model.Domain))

	if !validate.IsValidDomain(model.Domain) {
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest, "invalid domain", model.Domain)
		return
	}

	auth, err := v.entityRepo.SelectAuthByID(wc.Context(), id)
	if err != nil {
		logx.Error("failed to find auth", "id", sigData.ID, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	if len(auth) != 1 || auth[0].ID != id || auth[0].Locked {
		wc.ErrorJSON(http.StatusForbidden, errForbidden)
		return
	}

	encKey, err := base64.StdEncoding.DecodeString(auth[0].EncryptKey)
	if err != nil {
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	sig := signature.NewCustomSignature(sigData.ID, auth[0].Token, sigData.Alg, sigAlg)
	if !sig.Verify(req, sigData.Sig) {
		wc.ErrorJSON(http.StatusForbidden, errForbidden)
		return
	}

	var caDomain string
	reqDomainLevels := validate.CountDomainLevels(model.Domain)
	for _, domain := range auth[0].Domains {
		if validate.CountDomainLevels(domain)+1 != reqDomainLevels {
			continue
		}
		if !strings.HasSuffix(model.Domain, domain) {
			continue
		}
		caDomain = domain
		break
	}

	if len(caDomain) == 0 {
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest, "unsupported domain", model.Domain)
		return
	}

	enc, err := aesgcm.New(encKey)
	if err != nil {
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	ca, ok := v.certStore.Get(caDomain)
	if !ok {
		wc.ErrorJSON(http.StatusBadRequest, errInvalidRequest, "unsupported domain", model.Domain)
		return
	}

	exists, err := v.entityRepo.SelectCertNonRevokedByDomain(wc.Context(), model.Domain)
	if err != nil {
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	certModel := entity.Cert{
		Owner:   auth[0].ID,
		Domain:  model.Domain,
		Revoked: true,
	}

	resp := client.RenewalModel{
		Status: client.RenewalStatusIssued,
		Format: model.Format,
	}

	if len(exists) > 0 {
		for _, exist := range exists {
			if exist.Owner != certModel.Owner {
				resp.Status = client.RenewalStatusFail
				sendResponse(wc, &resp, enc, certModel.SerialNumber, certModel.Domain)
				return
			}

			if exist.ValidUntil.After(time.Now().AddDate(0, 0, -14)) && !model.Force {
				resp.Status = client.RenewalStatusActual
				sendResponse(wc, &resp, enc, certModel.SerialNumber, certModel.Domain)
				return
			}
		}

		if err = v.entityRepo.UpdateCertsAsRevoked(wc.Context(), certModel.Owner, certModel.Domain); err != nil {
			wc.ErrorJSON(http.StatusInternalServerError, err)
			return
		}
	}

	if err = v.entityRepo.CreateCert(wc.Context(), &certModel); err != nil {
		logx.Error("failed to create certificate",
			"domain", model.Domain, "owner", certModel.Owner, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	cfg := x509cert.Config{
		OCSPServer:            ca.CA.Cert.Certificate.OCSPServer,
		IssuingCertificateURL: []string{ca.Icu},
		CRLDistributionPoints: ca.CA.Cert.Certificate.CRLDistributionPoints,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	newCert, err := x509cert.NewCert(
		cfg, *ca.CA, 2048, time.Duration(ca.Days)*time.Hour*24, certModel.SerialNumber, model.Domain,
	)
	if err != nil {
		logx.Error("failed to create certificate", "sn", certModel.SerialNumber, "domain", model.Domain, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	certModel.Revoked = false
	certModel.CreatedAt = newCert.Cert.Certificate.NotBefore
	certModel.ValidUntil = newCert.Cert.Certificate.NotAfter
	certModel.Subject = cfg.ToSubject().String()

	fp, err := newCert.Cert.FingerPrint(entity.Hash)
	if err != nil {
		logx.Error("failed to create certificate fingerprint",
			"sn", certModel.SerialNumber, "domain", model.Domain, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}
	certModel.FingerPrint = hex.EncodeToString(fp)

	ikh, err := ca.CA.Cert.IssuerKeyHash(entity.Hash)
	if err != nil {
		logx.Error("failed to create certificate issuer key hash",
			"sn", certModel.SerialNumber, "domain", model.Domain, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}
	certModel.IssuerKeyHash = hex.EncodeToString(ikh)

	inh, err := ca.CA.Cert.IssuerNameHash(entity.Hash)
	if err != nil {
		logx.Error("failed to create certificate issuer name hash",
			"sn", certModel.SerialNumber, "domain", model.Domain, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}
	certModel.IssuerNameHash = hex.EncodeToString(inh)

	if err = v.entityRepo.UpdateCertBySerialNumber(wc.Context(), &certModel); err != nil {
		logx.Error("failed to update certificate",
			"sn", certModel.SerialNumber, "domain", model.Domain, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	switch model.Format {
	case client.RenewalFormatPEM:
		caB, err1 := ca.CA.Cert.EncodePEM()
		certB, err2 := newCert.Cert.EncodePEM()
		keyB, err3 := newCert.Key.EncodePEM()
		if err1 != nil || err2 != nil || err3 != nil {
			logx.Error("failed to build PEM",
				"sn", certModel.SerialNumber, "domain", model.Domain, "err", errors.Wrap(err1, err2, err3))
			wc.ErrorJSON(http.StatusInternalServerError, errors.Wrap(err1, err2, err3))
			return
		}
		resp.CA = string(caB)
		resp.Cert = string(certB)
		resp.Key = string(keyB)

	default:
		caB, err1 := ca.CA.Cert.EncodeDER()
		certB, err2 := newCert.Cert.EncodeDER()
		keyB, err3 := newCert.Key.EncodeDER()
		if err1 != nil || err2 != nil || err3 != nil {
			logx.Error("failed to build DER",
				"sn", certModel.SerialNumber, "domain", model.Domain, "err", errors.Wrap(err1, err2, err3))
			wc.ErrorJSON(http.StatusInternalServerError, errors.Wrap(err1, err2, err3))
			return
		}
		resp.CA = base64.StdEncoding.EncodeToString(caB)
		resp.Cert = base64.StdEncoding.EncodeToString(certB)
		resp.Key = base64.StdEncoding.EncodeToString(keyB)
	}

	sendResponse(wc, &resp, enc, certModel.SerialNumber, model.Domain)
}

func sendResponse(wc web.Ctx, resp *client.RenewalModel, enc *aesgcm.Codec, sn int64, domain string) {
	b, err := json.Marshal(resp)
	if err != nil {
		logx.Error("failed to marshal response", "sn", sn, "domain", domain, "err", err)
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	encBody, err := enc.Encrypt(b)
	if err != nil {
		wc.ErrorJSON(http.StatusInternalServerError, err)
		return
	}

	wc.Bytes(http.StatusOK, encBody)
}
