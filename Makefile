SHELL := /usr/bin/env bash
export PATH := $(PATH):$(HOME)/.cargo/bin

.PHONY: check check-ascii check-rust check-guard check-plugin build-plugin

check: check-ascii check-rust check-guard check-plugin

check-ascii:
	@if LC_ALL=C grep -I -n '[^[:print:][:space:]]' \
		Cargo.toml Makefile README.md docs/PROPOSAL.md vm/build-initramfs.sh \
		crates/sb-proto/Cargo.toml crates/sb-proto/src/*.rs \
		crates/sb-enclave/Cargo.toml crates/sb-enclave/src/*.rs \
		crates/sb-host/Cargo.toml crates/sb-host/src/*.rs \
		plugin/build.gradle.kts plugin/settings.gradle.kts plugin/gradle.properties \
		plugin/src/main/resources/META-INF/plugin.xml \
		plugin/src/main/kotlin/me/vespoli/secretbridge/*.kt \
		plugin/src/test/kotlin/me/vespoli/secretbridge/*.kt; then \
		echo "ERROR: non-7-bit-ASCII bytes detected in authored sources"; \
		exit 1; \
	fi
	@bash -n vm/build-initramfs.sh

check-rust:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --offline --locked -- -D warnings
	cargo test --workspace --offline --locked
	cargo build --bins --offline --locked

check-guard:
	node --test .guard/tests/guard.ts

check-plugin:
	./plugin/gradlew -p plugin check --offline --no-daemon --max-workers=2

build-plugin:
	./plugin/gradlew -p plugin check buildPlugin --no-daemon --max-workers=2
