/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package entity

//go:generate goppy gen-orm --dialect=pgsql --db-read=slave --db-write=master --index=1000 --sql-dir=../../migrations

import "go.osspkg.com/goppy/v2/plugins"

var Plugin = plugins.Kind{
	Inject: newRepo,
}
