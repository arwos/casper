SHELL=/bin/bash


.PHONY: install
install:
	go install go.osspkg.com/goppy/v2/cmd/goppy@latest
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

run_client:
	go run -race cmd/casper-cli/main.go ca \
		--cn='Dev Root CA L0' \
		--org='Dev Team' \
		--deadline=7300 \
		--crl='http://crl.demo.local/root-l0.crl' \
		--ocsp='http://ocsp.demo.local/root-l0' \
		--output=./build

	go run -race cmd/casper-cli/main.go ca \
		--cn='Dev Web CA L1' \
		--org='Dev Team' \
		--deadline=3650 \
		--ca-cert=./build/dev_root_ca_l0.crt \
		--ca-key=./build/dev_root_ca_l0.key \
		--ocsp='http://ocsp.demo.local/root-l1' \
		--crl='http://crl.demo.local/root-l1.crl' \
		--icu='http://crt.demo.local/root-l0.crt' \
		--output=./build

run_server:
	go run -race cmd/casper-server/main.go --config=config/config.dev.yaml