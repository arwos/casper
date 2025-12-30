#!/bin/bash

set -e

echo "example generate CA"
exit 1

#------------------------------------------------------------------------------------------

ORG="Example Org"
ROOT="Example Root A0"
INTER="Example Intermediate B0"
HOST="pki.example.com"

casper-cli ca \
		--cn="${ROOT}" \
		--org="${ORG}" \
		--deadline=1825 \
		--alg=ecdsa256 \
		--filename=root \
		--output=.

casper-cli ca \
		--cn="${INTER}" \
		--org="${ORG}" \
		--deadline=730 \
		--ca-cert=./root.crt \
		--ca-key=./root.key \
		--alg=ecdsa256 \
		--icu="http://${HOST}/icu/example-root-a0.crt" \
		--ocsp="http://${HOST}/ocsp/example-inter-b0" \
		--crl="http://${HOST}/crl/example-inter-b0.crl" \
		--filename=intermediate \
		--output=.

chown casper:casper *.{key,crt}