/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package internal

import (
	"go.osspkg.com/goppy/v2/plugins"

	"go.arwos.org/casper/internal/api"
	"go.arwos.org/casper/internal/entity"
	"go.arwos.org/casper/internal/pkgs/certs"
)

var Plugins = plugins.Inject(
	api.Plugin,
	entity.Plugin,
	certs.Plugin,
)
