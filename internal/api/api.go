/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package api

import (
	"context"
	"fmt"

	"go.osspkg.com/goppy/v2/web"

	"go.arwos.org/casper/internal/entity"
	"go.arwos.org/casper/internal/pkgs/certs"
)

type API struct {
	apiRoute  web.Router
	ocspRoute web.Router
	crlRoute  web.Router
	crtRoute  web.Router

	entityRepo *entity.Repo
	certStore  *certs.Store
}

func NewAPI(sp web.ServerPool, r *entity.Repo, cs *certs.Store) (*API, error) {
	obj := &API{
		entityRepo: r,
		certStore:  cs,
	}
	var ok bool
	if obj.apiRoute, ok = sp.ByTag("main"); !ok {
		return nil, fmt.Errorf("'main' server does not exist")
	}
	if obj.ocspRoute, ok = sp.ByTag("ocsp"); !ok {
		return nil, fmt.Errorf("'ocsp' server does not exist")
	}
	if obj.crlRoute, ok = sp.ByTag("crl"); !ok {
		return nil, fmt.Errorf("'crl' server does not exist")
	}
	if obj.crtRoute, ok = sp.ByTag("crt"); !ok {
		return nil, fmt.Errorf("'crt' server does not exist")
	}

	return obj, nil
}

func (v *API) Up(ctx context.Context) error {
	v.addOCSPHandlers()
	v.addCrtHandlers()
	v.addCrlHandlers()
	v.updateCrlTicker(ctx)

	return nil
}

func (v *API) Down() error {
	return nil
}
