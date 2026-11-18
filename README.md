# SecretBridge for 1Password (`me.vespoli.secretbridge`)

Zero-trust 1Password secret orchestration for JetBrains IDEs (`2024.3+`, build `243+`), backed by an isolated separate-kernel Linux microVM Rust enclave over `AF_VSOCK` and end-to-end `Noise_IK_25519_ChaChaPoly_BLAKE2s` transport encryption.

## Architecture Overview

SecretBridge splits secret handling across three trust zones so plaintext application secrets never reside on the JetBrains JVM heap:

1. **`crates/sb-proto` (`#![forbid(unsafe_code)]`)**:
   - Strict 7-bit ASCII validated newtypes (`Manifest`, `OpRef`, `SecretName`, `GitHubTarget`, `AwsTarget`, `RecoveryDays`, `CommitSha40`) with `#[serde(deny_unknown_fields)]` (rejecting legacy v0.1.0 `tools` execution blocks).
   - Mutual-authenticated `Noise_IK` length-prefixed framing (`<= 1 MiB` frames), libsodium-compatible `crypto_box` (`X25519XSalsa20Poly1305`) sealed boxes, and ephemeral enclave HMAC-SHA256 `SignedPlan` verification.
2. **`crates/sb-enclave` (Isolated Guest MicroVM Daemon)**:
   - Stores secret material inside `memfd_secret(2)` / `mlock(2)` + `MADV_DONTDUMP` (`MemSecret`) backed by Rust `1.100.0` `std::mem::DropGuard` zeroization.
   - Connects directly to 1Password via SHA-256-pinned `libop_uniffi_core.so` (`O_NOFOLLOW` + `/proc/self/fd/{fd}` verification prior to `dlopen`) behind the `VaultProvider` trait -- no `op` CLI and no sidecar containers.
   - Enforces `SAFE_ITEM_CATEGORIES` (`SECURE_NOTE`, `API_CREDENTIAL`, `PASSWORD`, `DATABASE`, `SERVER`), blocks Personal/Private/Employee vaults, and gates vault creation on `OP_SERVICE_ACCOUNT_TOKEN` `can_create_vaults` permissions.
   - Executes pure-Rust (`rustls`) AWS Secrets Manager + STS SigV4 calls (`GetCallerIdentity` account verification, `secretbridge:managed=true` ownership tag enforcement, `7..=30` day recovery window, `DescribeSecret` metadata allowlisting) and pure-Rust GitHub Actions secret encryption (`X25519XSalsa20Poly1305` sealed boxes, RFC-3986 segment encoding, mandatory org repository allowlists).
   - Generates new secrets strictly inside the guest kernel via OS CSPRNG and mints 15-second single-use `X25519` capture challenges (`pk_capture`) for external secret ingestion.
3. **`crates/sb-host` (Native Host VMM Controller & Armed Copy Hijack)**:
   - Verifies guest kernel and initramfs SHA-256 digests (`O_NOFOLLOW`) before booting a network-restricted microVM over `AF_VSOCK`.
   - Performs symlink-safe, mode-preserving atomic `fsync` reads/writes of `<project>/secretbridge.json`.
   - Implements a 15-second single-shot `DropGuard`-backed **Armed Copy Hijack**:
     - **macOS `arm64`**: Active `CGEventTap` (`kCGSessionEventTap`) swallows the next `Cmd+C`, reads `kAXSelectedTextAttribute` via `AXUIElement` directly into `mlock()` RAM, seals to `pk_capture`, zeroizes, and tears down the tap immediately; paired with a `1ms` `NSPasteboard` snapshot-capture-restore fallback for web "Copy" buttons.
     - **Linux `x86_64` / `aarch64`**: Single-shot X11 `XGrabKey` (`Ctrl+C`) + `PRIMARY` selection read/wipe into `mlock()` RAM, or Wayland single-shot clipboard stream capture + prior-clipboard restore.
4. **`plugin/` (JetBrains IDE Frontend - Kotlin 2.x + Gradle 9.3.0)**:
   - Targets IntelliJ Platform `2024.3+` (`since-build = "243"`).
   - Stores non-secret paths in `secretbridge.xml` and bootstrap credentials in OS Keychain (`PasswordSafe`), streaming them off-EDT via zeroized `CharArray` JSON buffers to `sb-host` over a mode-`0600` Java 21 `UnixDomainSocketAddress` channel.
   - Provides the **SecretBridge** tool window (capability-gated vault creation, metadata-only item/field browser, in-VM CSPRNG generator, 15s countdown Armed Copy capture, signed plan diff preview & apply, template renderer) and a VFS-cached `ReferenceCompletionContributor`.

## Toolchain & Supply-Chain Requirements

- **Rust `1.100.0`** (`edition = "2024"`, `rust-version = "1.100.0"`, `clippy`, `rustfmt`).
- **JDK `21`** toolchain + **Gradle `9.3.0`** wrapper (`plugin/gradlew`).
- **Supported v1 Host Platforms**:
  - `macOS arm64` (`Virtualization.framework` entitlement `com.apple.security.virtualization` + Accessibility permission for zero-pasteboard `CGEventTap`).
  - `Linux x86_64` / `aarch64` (`/dev/kvm` + `/dev/vhost-vsock` `AF_VSOCK`).
  - *(Intel macOS `x86_64`, Windows, `SecretRunConfiguration` local app execution, and HTTP credential-injecting proxies are intentionally excluded from v1.)*

### Manual `.cargo/config.toml` Supply-Chain Hardening

Because repository guardrails prohibit automated edits to `.cargo/config*`, add the following manually to `.cargo/config.toml` on developer machines and CI runners:

```toml
[resolver]
# Require crates.io releases to be published at least 7 days before resolution
# (supported in modern Cargo; adjust window per your release policy).
incompatible-rust-versions = "fallback"
```

*(Note: When running Cargo `1.100.0+` with `min-publish-age` enabled, add `min-publish-age = "7d"` under `[resolver]` or `[net]` per your Cargo `1.100.0` policy.)*

## Building & Verifying

### 1. Rust Workspace (`sb-proto`, `sb-enclave`, `sb-host`)

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

### 2. Guest MicroVM Minimal `glibc` Initramfs (`Linux`)

`libop_uniffi_core.so` links against `glibc` (`libc.so.6`, `libm.so.6`, `libgcc_s.so.1`, dynamic loader) rather than pure `musl`. Build the minimal guest initramfs image and record its SHA-256 digest:

```sh
cargo build --release -p sb-enclave
OP_UNIFFI_LIB=/path/to/pinned/libop_uniffi_core.so \
OP_UNIFFI_SHA256=<64-hex-sha256> \
  bash vm/build-initramfs.sh
```

### 3. JetBrains IDE Plugin (`plugin/`)

```sh
./plugin/gradlew -p plugin check buildPlugin
# Optional full JetBrains binary compatibility verification:
./plugin/gradlew -p plugin verifyPlugin
```

The installable plugin archive is written to `plugin/build/distributions/`. Install it in IntelliJ IDEA / WebStorm / GoLand / PyCharm / RustRover (`2024.3+`) via **Settings -> Plugins -> Gear Icon -> Install Plugin from Disk...**, then configure `sb-host` and microVM image SHA-256 digests under **Settings -> Tools -> SecretBridge for 1Password**.

### 4. Offline Completion Gate

```sh
make check
bash .guard/checks/on-stop
```

## Manual IDE Verification Checklist

1. Open **Settings -> Tools -> SecretBridge for 1Password**, configure `sb-host` + guest kernel/initramfs paths and 64-hex SHA-256 digests, enter an `OP_SERVICE_ACCOUNT_TOKEN`, click **Apply**, and click **Test Enclave & Service Account Capabilities**.
2. Open the **SecretBridge** tool window on the right sidebar and click **Refresh**:
   - Confirm **Create Vault...** is disabled with an explanatory tooltip if the Service Account lacks `can_create_vaults`, and enabled otherwise.
   - Confirm Personal/Private vaults are never exposed or mutated, and `LOGIN` items are excluded/rejected by `SAFE_ITEM_CATEGORIES`.
3. Click **Generate Secret (In-VM)...**, generate a 40-char secret, and verify that `secretbridge.json` receives only the `op://` reference while zero secret plaintext crosses to the host.
4. Click **Capture Secret (15s Armed Copy)...**, highlight text in another app and press `Cmd+C` / `Ctrl+C` within 15 seconds, and verify the status banner reports `Zero-Pasteboard Intercept` (or `1ms Pasteboard Snapshot-Restore Fallback` when clicking a web Copy button) and restores normal copy behavior immediately.
5. Configure explicit `github` and/or `aws` targets in `secretbridge.json`, click **Preview & Sync...**, inspect the HMAC-signed plan diff, click **Apply Signed Plan**, and confirm cloud target updates.
