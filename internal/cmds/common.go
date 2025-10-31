/*
 *  Copyright (c) 2025 Mikhail Knyazhev <markus621@yandex.com>. All rights reserved.
 *  Use of this source code is governed by a GPL-3.0 license that can be found in the LICENSE file.
 */

package cmds

import (
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"sync/atomic"

	"go.osspkg.com/errors"
	"go.osspkg.com/ioutils/fs"
)

var sslCertGroup = atomic.Int64{}

func init() {
	detectSSLCertGroup()
}

var _algorithms = map[string]x509.SignatureAlgorithm{
	"rsa256":   x509.SHA256WithRSA,
	"rsa384":   x509.SHA384WithRSA,
	"rsa512":   x509.SHA512WithRSA,
	"ecdsa256": x509.ECDSAWithSHA256,
	"ecdsa384": x509.ECDSAWithSHA384,
	"ecdsa512": x509.ECDSAWithSHA512,
}

func setLinuxAccess(dir, filename string) (err error) {
	if file := fmt.Sprintf("%s/%s.crt", dir, filename); fs.FileExist(file) {
		err = errors.Wrap(err,
			errors.Wrapf(os.Chmod(file, 0644), "failed to chmod certificate"),
			errors.Wrapf(os.Chown(file, 0, int(sslCertGroup.Load())), "failed to chown certificate"),
		)
	}
	if file := fmt.Sprintf("%s/%s.key", dir, filename); fs.FileExist(file) {
		err = errors.Wrap(err,
			errors.Wrapf(os.Chmod(file, 0640), "failed to chmod private key"),
			errors.Wrapf(os.Chown(file, 0, int(sslCertGroup.Load())), "failed to chown private key"),
		)
	}
	return
}

func errWrap(err error, domain string) {
	if err == nil {
		return
	}
	fmt.Println("[ERROR]", err.Error(), "(domains: ", domain, ")")
}

func detectSSLCertGroup() {
	var rex = regexp.MustCompile(`(?m)^ssl\-cert\:x\:(\d+)`)

	b, err := os.ReadFile("/etc/group")
	if err != nil {
		fmt.Println("[WARN] detecting SSL certificate group Err:", err)
		return
	}

	if len(b) == 0 {
		return
	}

	res := rex.FindStringSubmatch(string(b))
	if len(res) < 2 {
		return
	}

	val, err := strconv.ParseInt(res[1], 10, 64)
	if err != nil {
		fmt.Println("[WARN] detecting SSL certificate group Err:", err)
		return
	}

	sslCertGroup.Store(val)
}
