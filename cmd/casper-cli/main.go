/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package main

import (
	"go.osspkg.com/console"

	"go.arwos.org/casper/internal/cmds"
)

func main() {
	cli := console.New("casper-cli", "Casper Certificate Management Client")
	cli.AddCommand(cmds.GenerateCA())
	cli.AddCommand(cmds.RenewalCert())
	cli.Exec()
}
