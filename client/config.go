/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package client

type Config struct {
	Address    string `yaml:"address"`
	Proxy      string `yaml:"proxy"`
	AuthID     string `yaml:"auth_id"`
	AuthKey    string `yaml:"auth_key"`
	EncryptKey string `yaml:"encrypt_key"`
}
