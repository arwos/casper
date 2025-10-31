#!/bin/bash

set -e

echo "example generate CA"
exit 1

#------------------------------------------------------------------------------------------

ORG="Dev Team"
ROOT="Dev Root CA L0"
INTER="Dev Web Intermediate L1"
HOST="127.0.0.3:20000"
EMAIL="pki@localhost"

casper-cli ca \
		--cn="${ROOT}" \
		--org="${ORG}" \
		--deadline=7300 \
		--alg=ecdsa512 \
		--ocsp="http://${HOST}/root/root-l0" \
		--crl="http://${HOST}/crl/root-l0.crl" \
		--icu="http://${HOST}/icu/root-l0.crt" \
		--email="${EMAIL}" \
		--filename=root \
		--output=.

casper-cli ca \
		--cn="${INTER}" \
		--org="${ORG}" \
		--deadline=3650 \
		--ca-cert=./root.crt \
		--ca-key=./root.key \
		--alg=ecdsa512 \
		--ocsp="http://${HOST}/root/root-l1" \
		--crl="http://${HOST}/crl/root-l1.crl" \
		--icu="http://${HOST}/icu/root-l0.crt" \
		--email="${EMAIL}" \
		--filename=intermediate \
		--output=.
