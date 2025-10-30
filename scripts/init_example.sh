#!/bin/bash

ORG="Dev Team"
ROOT="Dev Root CA L0"
INTER="Dev Web CA L1"
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
		--output=.

casper-cli ca \
		--cn="${INTER}" \
		--org="${ORG}" \
		--deadline=3650 \
		--ca-cert=./dev_root_ca_l0.crt \
		--ca-key=./dev_root_ca_l0.key \
		--alg=ecdsa512 \
		--ocsp="http://${HOST}/root/root-l1" \
		--crl="http://${HOST}/crl/root-l1.crl" \
		--icu="http://${HOST}/icu/root-l0.crt" \
		--email="${EMAIL}" \
		--output=.