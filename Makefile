# sdb Makefile

.PHONY: all test static

SHELL = /usr/bin/env sh -eu

all: test

test: static
	cargo build --all-targets
	RUST_BACKTRACE=1 cargo test

static:
	cargo fmt -- --check
	cargo clippy -- -Dwarnings
	@if [ "${CI}x" != "x" ]; then git diff --exit-code; fi
