SHELL := /usr/bin/env bash
DEFAULT_JDK21 := $(wildcard $(HOME)/.jdks/jdk-21*)
ifneq ($(DEFAULT_JDK21),)
export JAVA_HOME ?= $(firstword $(DEFAULT_JDK21))
export PATH := $(JAVA_HOME)/bin:$(HOME)/.local/bin:$(HOME)/.cargo/bin:$(PATH)
else
export PATH := $(HOME)/.local/bin:$(HOME)/.cargo/bin:$(PATH)
endif

CARGO_NET_FLAGS ?= $(if $(SB_ONLINE),,--offline)
GRADLE_NET_FLAGS ?= $(if $(SB_ONLINE),,--offline)

.PHONY: check check-ascii check-rust check-guard check-plugin build-plugin verify-plugin

check: check-ascii check-rust check-guard check-plugin

check-ascii:
	@if LC_ALL=C grep -I -n '[^[:print:][:space:]]' \
		Cargo.toml Makefile README.md .gitleaks.toml .gitleaksignore \
		docs/PROPOSAL.md vm/build-initramfs.sh \
		crates/sb-proto/Cargo.toml crates/sb-proto/src/*.rs \
		crates/sb-enclave/Cargo.toml crates/sb-enclave/src/*.rs \
		crates/sb-host/Cargo.toml crates/sb-host/src/*.rs \
		plugin/build.gradle.kts plugin/settings.gradle.kts plugin/gradle.properties \
		plugin/gradle/wrapper/gradle-wrapper.properties \
		plugin/src/main/resources/META-INF/plugin.xml \
		plugin/src/main/kotlin/me/vespoli/secretbridge/*.kt \
		plugin/src/test/kotlin/me/vespoli/secretbridge/*.kt; then \
		echo "ERROR: non-7-bit-ASCII bytes detected in authored sources"; \
		exit 1; \
	fi
	@bash -n vm/build-initramfs.sh

check-rust:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets $(CARGO_NET_FLAGS) --locked -- -D warnings
	cargo test --workspace $(CARGO_NET_FLAGS) --locked
	cargo build --bins $(CARGO_NET_FLAGS) --locked
	chmod go-w target/debug/sb-host target/debug/sb-enclave

check-guard:
	node --test .guard/tests/guard.ts

check-plugin: check-rust
	./plugin/gradlew -p plugin check $(GRADLE_NET_FLAGS) --no-daemon --max-workers=2

build-plugin: check-rust
	./plugin/gradlew -p plugin check buildPlugin $(GRADLE_NET_FLAGS) --no-daemon --max-workers=2

verify-plugin:
	./plugin/gradlew -p plugin verifyPlugin $(GRADLE_NET_FLAGS) --no-daemon --max-workers=2
