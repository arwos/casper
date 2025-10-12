/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package main

import (
	"go.osspkg.com/goppy/v2"
	"go.osspkg.com/goppy/v2/metrics"
	"go.osspkg.com/goppy/v2/orm"
	"go.osspkg.com/goppy/v2/orm/clients/pgsql"
	"go.osspkg.com/goppy/v2/web"
)

var Version = "v0.0.0-dev"

func main() {
	app := goppy.New("casper-server", Version, "Certificate Management Server")

	app.Plugins(
		metrics.WithServer(),
		web.WithServer(),
		orm.WithORM(pgsql.Name),
		orm.WithMigration(),
	)

	app.Run()
}
