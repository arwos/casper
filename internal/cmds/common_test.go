package cmds

import (
	"fmt"
	"regexp"
	"testing"
)

func Test_detectSSLCertGroup(t *testing.T) {
	var rex = regexp.MustCompile(`(?m)^ssl\-cert\:x\:(\d+)`)

	b := `user:x:1000:
ssl-cert:x:109:postgres
postgres:x:110:
casper:x:996:
`

	fmt.Println(rex.FindStringSubmatch(b))
}
