SHELL=/bin/bash


.PHONY: install
install:
	go install go.osspkg.com/goppy/v2/cmd/goppy@v2.4.5
	goppy setup-lib

.PHONY: lint
lint:
	goppy lint

.PHONY: license
license:
	goppy license

.PHONY: build
build:
	goppy build --arch=amd64

.PHONY: tests
tests:
	goppy test

.PHONY: pre-commit
pre-commit: install license lint tests build

.PHONY: ci
ci: pre-commit

run_client_ca:
	go run -race cmd/casper-cli/main.go ca \
		--cn='Dev Root CA L0' \
		--org='Dev Team' \
		--country='RU' \
		--deadline=7300 \
		--alg=ecdsa512 \
		--ocsp='http://pki.demo.local/root/root-l0' \
		--cps='http://pki.demo.local/docs/cps.pdf' \
		--crl='http://pki.demo.local/crl/root-l0.crl' \
		--icu='http://pki.demo.local/icu/root-l0.crt' \
		--email='pki@demo.local' \
		--output=./build

	go run -race cmd/casper-cli/main.go ca \
		--cn='Dev Web CA L1' \
		--org='Dev Team' \
		--deadline=3650 \
		--ca-cert=./build/dev_root_ca_l0.crt \
		--ca-key=./build/dev_root_ca_l0.key \
		--alg=ecdsa512 \
		--ocsp='http://pki.demo.local/root/root-l1' \
		--cps='http://pki.demo.local/docs/cps.pdf' \
		--crl='http://pki.demo.local/crl/root-l1.crl' \
		--icu='http://pki.demo.local/icu/root-l0.crt' \
		--email='pki@demo.local' \
		--output=./build

run_client_renewal:
	go run -race cmd/casper-cli/main.go renewal \
		--address='http://127.0.0.1:20001' \
		--auth-id='c958e408-d558-4964-aac1-960f815c0c2e' \
		--auth-key='Ae8fL1pAB+83qaob3cQkX/bGHxDycUjW' \
		--domains='a.demo.com' \
		--alg=ecdsa256 \
		--force \
		--output=./build

run_client_ocsp:
	openssl x509 -noout -ocsp_uri -in ./build/a_demo_com.crt
	openssl ocsp \
		-issuer ./build/a_demo_com.chain.crt \
		-cert ./build/a_demo_com.crt \
		-text -url http://127.0.0.1:20002/root/root-l1


run_server:
	go run -race cmd/casper-server/main.go --config=config/config.dev.yaml