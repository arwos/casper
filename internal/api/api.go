/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package api

import (
	"context"
	"fmt"

	"go.osspkg.com/goppy/v2/web"
	"go.osspkg.com/logx"
	"go.osspkg.com/routine/tick"

	"go.arwos.org/casper/internal/entity"
	"go.arwos.org/casper/internal/pkgs/certs"
)

type API struct {
	apiRoute web.Router
	pkiRoute web.Router

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
	if obj.pkiRoute, ok = sp.ByTag("pki"); !ok {
		return nil, fmt.Errorf("'pki' server does not exist")
	}

	return obj, nil
}

func (v *API) Up(ctx context.Context) error {
	v.addApiHandlers()
	v.addCrlHandlers()
	v.addIcuHandlers()
	v.addOCSPHandlers()

	tik := tick.Ticker{
		OnError: func(name string, err error) {
			logx.Error(name, "err", err)
		},
		Calls: []tick.Config{
			v.tickerConfigCleanCrl(),
			v.tickerConfigBuildCrl(),
		},
	}

	go tik.Run(ctx)

	return nil
}

func (v *API) Down() error {
	return nil
}
