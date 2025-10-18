SHELL=/bin/bash


.PHONY: install
install:
	go install go.osspkg.com/goppy/v2/cmd/goppy@v2.4.5-0.20251018025447-a7cb8181eb99
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
		--deadline=7300 \
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

run_client_renewal:
	go run -race cmd/casper-cli/main.go renewal \
		--address='http://127.0.0.1:20001' \
		--auth-id='1' \
		--auth-key='Ae8fL1pAB+83qaob3cQkX/bGHxDycUjW' \
		--domain='a.demo.com' \
		--decrypt-key='rckSUuqSFhuxe5LZXuu+BgOpL+yqgyVnc9KbSR6QQlI=' \
		--force \
		--output=./build

run_server:
	go run -race cmd/casper-server/main.go --config=config/config.dev.yaml