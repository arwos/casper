#!/bin/bash

set -e

echo "example generate CA"
exit 1

#------------------------------------------------------------------------------------------

ORG="Dev Team"
ROOT="Dev Root CA L0"
INTER="Dev Web Intermediate L1"
HOST="127.0.0.3:20000"

casper-cli ca \
		--cn="${ROOT}" \
		--org="${ORG}" \
		--deadline=3650 \
		--alg=ecdsa256 \
		--cps="http://${HOST}/cps/root-l0.html" \
		--filename=root \
		--output=.

casper-cli ca \
		--cn="${INTER}" \
		--org="${ORG}" \
		--deadline=1825 \
		--ca-cert=./root.crt \
		--ca-key=./root.key \
		--alg=ecdsa256 \
		--icu="http://${HOST}/icu/root-l0.crt" \
		--ocsp="http://${HOST}/ocsp/root-l0" \
		--crl="http://${HOST}/crl/root-l0.crl" \
		--cps="http://${HOST}/cps/root-l0.html" \
		--filename=intermediate \
		--output=.
