# sbd Makefile

.PHONY: all publish-all publish test static

SHELL = /usr/bin/env sh -eu

all: test

publish-all:
	$(MAKE) publish crate=sbd-client
	$(MAKE) publish crate=sbd-server
	$(MAKE) publish crate=sbd-o-bahn-client-tester
	$(MAKE) publish crate=sbd-o-bahn-server-tester
	$(MAKE) publish crate=sbd-e2e-crypto-client

publish:
	@case "$(crate)" in \
		sbd-client) \
			export MANIFEST="./rust/sbd-client/Cargo.toml"; \
			;; \
		sbd-server) \
			export MANIFEST="./rust/sbd-server/Cargo.toml"; \
			;; \
		sbd-o-bahn-client-tester) \
			export MANIFEST="./rust/sbd-o-bahn-client-tester/Cargo.toml"; \
			;; \
		sbd-o-bahn-server-tester) \
			export MANIFEST="./rust/sbd-o-bahn-server-tester/Cargo.toml"; \
			;; \
		sbd-e2e-crypto-client) \
			export MANIFEST="./rust/sbd-e2e-crypto-client/Cargo.toml"; \
			;; \
		*) \
			echo "USAGE: make publish crate=sbd-client"; \
			echo "USAGE: make publish crate=sbd-server"; \
			echo "USAGE: make publish crate=sbd-o-bahn-client-tester"; \
			echo "USAGE: make publish crate=sbd-o-bahn-server-tester"; \
			echo "USAGE: make publish crate=sbd-e2e-crypto-client"; \
			exit 1; \
			;; \
	esac; \
	export VER="v$$(grep version $${MANIFEST} | head -1 | cut -d ' ' -f 3 | cut -d \" -f 2)"; \
	echo "publish $(crate) $${MANIFEST} $${VER}"; \
	git diff --exit-code; \
	cargo publish --manifest-path $${MANIFEST}; \
	git tag -a "$(crate)-$${VER}" -m "$(crate)-$${VER}"; \
	git push --tags;

test: static
	cargo build --all-targets
	RUST_BACKTRACE=1 cargo test

static:
	cargo fmt -- --check
	cargo clippy -- -Dwarnings
	@if [ "${CI}x" != "x" ]; then git diff --exit-code; fi
