# SecretBridge for 1Password (`me.vespoli.secretbridge`)

Zero-trust 1Password secret orchestration for JetBrains IDEs (`2024.3+`, build `243+`), backed by an isolated separate-kernel Linux microVM Rust enclave over `AF_VSOCK` and true end-to-end `Noise_IK_25519_ChaChaPoly_BLAKE2s` transport encryption between the Kotlin IDE plugin and the guest enclave.

## Architecture Overview

SecretBridge splits secret handling across three trust zones so plaintext application secrets never reside on the JetBrains JVM heap or in the host bridge:

1. **`crates/sb-proto` (`#![forbid(unsafe_code)]`)**:
   - Strict 7-bit ASCII validated newtypes (`Manifest`, `OpRef`, `SecretName`, `GitHubTarget`, `AwsTarget`, `RecoveryDays`, `CommitSha40`) with `#[serde(deny_unknown_fields)]` (rejecting legacy v0.1.0 `tools` execution blocks).
   - Mutually-authenticated `Noise_IK` length-prefixed framing (`<= 1 MiB` messages, synchronized `1,024`-frame transport cipherstate rekeying), libsodium-compatible `crypto_box` (`X25519XSalsa20Poly1305`) sealed boxes, and canonical RFC-8785-sorted enclave HMAC-SHA256 `SignedPlan` verification.
2. **`crates/sb-enclave` (Isolated Guest MicroVM Daemon)**:
   - Runs as hardened Linux PID 1 inside a minimal `glibc` initramfs (`MS_NOSUID | MS_NOEXEC | MS_NODEV` pseudo-filesystems, pure-Rust `ioctl` + RFC 2131 DHCPv4 lease & T1 renewal bring-up, child reaping, `RB_POWER_OFF` halt, zero guest shell).
   - Generates a fresh ephemeral `Noise_IK` static keypair strictly inside guest `MemSecret` (`memfd_secret(2)` / `mlock(2)` + `MADV_DONTDUMP`, Rust `1.100.0` `std::mem::DropGuard` zeroization) on every boot so **zero private keys are ever embedded in host-readable `initramfs.cpio.gz`**.
   - Connects directly to 1Password via SHA-256-pinned `libop_uniffi_core.so` (`O_NOFOLLOW` + `/proc/self/fd/{fd}` verification prior to `dlopen`, contract version verification, async `RustFuture` polling for `init_client`, `release_client(u64)`, and `RustBuffer`/`ForeignBytes`/`RustCallStatus` C-ABI) behind the `VaultProvider` trait -- no `op` CLI and no sidecar containers.
   - Enforces `SAFE_ITEM_CATEGORIES` (`SECURE_NOTE`, `API_CREDENTIAL`, `PASSWORD`, `DATABASE`, `SERVER`), blocks Personal/Private/Employee vaults, preserves unmanaged sibling fields byte-for-byte in `MemSecret` during updates, and gates vault creation on `OP_SERVICE_ACCOUNT_TOKEN` `can_create_vaults` permissions.
   - Executes pure-Rust (`rustls`) AWS Secrets Manager + STS SigV4 calls (`GetCallerIdentity` account verification, mandatory non-empty `allowed_aws_account_ids` allowlist, `secretbridge:managed=true` ownership tag enforcement, `7..=30` day recovery window, `DescribeSecret` metadata allowlisting) and pure-Rust GitHub Actions secret encryption (`X25519XSalsa20Poly1305` sealed boxes, RFC-3986 segment encoding, mandatory non-empty `allowed_github_owners` and org repository allowlists, explicit opt-in or `PrepareGithub` adoption before overwriting or deleting unmanaged GitHub secrets).
   - Generates new secrets strictly inside the guest kernel via OS CSPRNG and mints 15-second single-use `X25519` capture challenges (`pk_capture`) for external secret ingestion.
3. **`crates/sb-host` (Native Host VMM Controller & Blind Frame Relay)**:
   - Verifies guest kernel, initramfs, and VMM binary SHA-256 digests (`openat(..., O_DIRECTORY | O_NOFOLLOW)` non-world-writable ancestor verification) into write-sealed anonymous `memfd_create` descriptors (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`) on Linux (or `0400` private copies on macOS) before booting a network-restricted microVM (`Virtualization.framework` `VZVirtualMachine` + retained `VZVirtioSocketConnection` on `macOS arm64`; `/dev/kvm` + `/dev/vhost-vsock` with QEMU `-netdev user,id=net0,restrict=on` + a host `AF_VSOCK` `:443`-only public-unicast `CONNECT` egress proxy on Linux `x86_64`/`aarch64` while TLS 1.3 terminates end-to-end inside `sb-enclave`).
   - Acts purely as an untrusted raw frame relay (`HostCommand::NoiseTunnel`) for `Noise_IK` ciphertext between the IDE and `sb-enclave` -- `sb-host` holds zero `Noise_IK` private keys.
   - Performs symlink-safe, `flock`-serialized, mode-preserving atomic `fsync` reads/writes strictly targeting `<project>/secretbridge.json`.
   - Implements a 15-second single-shot `DropGuard`-backed **Armed Copy Hijack** (`HostCommand::CaptureAndSeal`, zero child subprocesses, streaming an explicit `{"armed":true}` readiness signal before starting the UI countdown):
     - **macOS `arm64`**: Active `CGEventTap` (`kCGSessionEventTap`) swallows the next `Cmd+C`, reads `kAXSelectedTextAttribute` via `AXUIElement` directly into `mlock()` RAM, seals to `pk_capture`, zeroizes, and tears down the tap immediately; paired with a `1ms` `NSPasteboard` snapshot-capture-restore fallback for web "Copy" buttons.
     - **Linux `x86_64` / `aarch64`**: Non-fatal `XInitThreads` + `XSetErrorHandler` X11 `XFixes` / `CLIPBOARD` capture (including multi-chunk ICCCM `INCR` up to `64 KiB`) into `mlock()` RAM with prior-clipboard restoration, or native Wayland wire-protocol (`zwlr-data-control-manager-v1` / `ext-data-control-manager-v1`) pipe stream capture without spawning `wl-paste` / `wl-copy` / `xclip`.
4. **`plugin/` (JetBrains IDE Frontend - Kotlin 2.x + Gradle 9.3.0)**:
   - Targets IntelliJ Platform `2024.3+` (`since-build = "243"`).
   - Terminates `Noise_IK_25519_ChaChaPoly_BLAKE2s` directly in pure JDK 21 (`NoiseIkSession.kt`, direct `SecureRandom` X25519 scalar generation + `"SunEC"` key agreement) using a persistent client static keypair stored in `PasswordSafe`.
   - Stores non-secret absolute binary paths and mandatory destination allowlists in `secretbridge.xml` and bootstrap credentials in OS Keychain (`PasswordSafe`), using a custom in-place zeroizing `PlainDocument` (`ZeroizingPasswordContent`) on all `JBPasswordField`s and streaming credentials off-EDT via zeroized `CharArray` JSON buffers (`JsonSecretChars`) directly through the `Noise_IK` session to `sb-enclave`.
   - Provides the **SecretBridge** tool window (capability-gated vault creation, metadata-only item/field browser, in-VM CSPRNG generator, readiness-gated 15s countdown Armed Copy capture, signed plan diff preview & apply, template renderer) and a VFS-cached `ReferenceCompletionContributor`.

### Trust Boundary Note (Workstation MicroVM vs. Hardware-Attested TEE)

On local developer workstations (`Linux` KVM and `macOS arm64` `Virtualization.framework` without hardware memory encryption such as AMD SEV-SNP, Intel TDX, or AWS Nitro Enclaves), the separate-kernel microVM isolates plaintext secrets, 1Password session state, and cloud signing keys from the JetBrains JVM heap, IDE plugins, crash dumps, swap, and unprivileged userland processes, while the host kernel and local VMM process remain part of the workstation Trusted Computing Base. For deployments requiring cryptographic isolation from an untrusted host OS, run `sb-enclave` inside a hardware-isolated / remote enclave and attach in **`Existing Vsock Enclave`** mode with a 64-hex **`enclavePubkeyHex`** pinned out-of-band.

## Toolchain & Supply-Chain Requirements

- **Rust `1.100.0`** (`edition = "2024"`, `rust-version = "1.100.0"`, `clippy`, `rustfmt`).
- **JDK `21`** toolchain + **Gradle `9.3.0`** wrapper (`plugin/gradlew`, SHA-256 verified).
- **Supported v1 Host Platforms**:
  - `macOS arm64` (`Virtualization.framework` entitlement `com.apple.security.virtualization` via `vm/macos-vz.entitlements.plist` + Accessibility & Input Monitoring permissions for zero-pasteboard `CGEventTap`).
  - `Linux x86_64` / `aarch64` (`/dev/kvm` + `/dev/vhost-vsock` `AF_VSOCK`).
  - *(Intel macOS `x86_64`, Windows, `SecretRunConfiguration` local app execution, and HTTP credential-injecting proxies are intentionally excluded from v1.)*

### Manual `.cargo/config.toml` Supply-Chain Hardening

Because repository guardrails prohibit automated edits to `.cargo/config*`, add the following manually to `.cargo/config.toml` on developer machines and CI runners:

```toml
[registry]
global-min-publish-age = "7 days"

[registries.crates-io]
min-publish-age = "7 days"

[resolver]
incompatible-rust-versions = "fallback"
```

## Building & Verifying

### 1. Rust Workspace (`sb-proto`, `sb-enclave`, `sb-host`)

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

*(On `macOS arm64`, `make check-rust` automatically ad-hoc signs `target/debug/sb-host` with `vm/macos-vz.entitlements.plist` so `Virtualization.framework` permits microVM creation.)*

### 2. Guest MicroVM Minimal `glibc` Initramfs (`Linux`)

`libop_uniffi_core.so` links against `glibc` (`libc.so.6`, `libm.so.6`, `libgcc_s.so.1`, dynamic loader) rather than pure `musl`. Build `sb-enclave` with the pinned `libop_uniffi_core.so` SHA-256 digest baked in at compile time (`SB_PINNED_OP_CORE_SHA256`) and package the minimal guest initramfs image:

```sh
SB_PINNED_OP_CORE_SHA256=<64-hex-sha256> cargo build --release --locked -p sb-enclave
OP_UNIFFI_LIB=/path/to/pinned/libop_uniffi_core.so \
OP_UNIFFI_SHA256=<64-hex-sha256> \
  bash vm/build-initramfs.sh
```

`vm/build-initramfs.sh` verifies that `sb-enclave` embeds `OP_UNIFFI_SHA256`, matches ELF `e_machine` across staged `glibc` libraries, and packages **zero** private keys into `initramfs.cpio.gz` (`sb-enclave` generates an ephemeral `Noise_IK` keypair in guest `MemSecret` RAM on every boot).

### 3. JetBrains IDE Plugin (`plugin/`)

```sh
./plugin/gradlew -p plugin check buildPlugin
# Optional full JetBrains binary compatibility verification:
./plugin/gradlew -p plugin verifyPlugin
```

The installable plugin archive is written to `plugin/build/distributions/`. Install it in IntelliJ IDEA / WebStorm / GoLand / PyCharm / RustRover (`2024.3+`) via **Settings -> Plugins -> Gear Icon -> Install Plugin from Disk...**, then configure the absolute `/path/to/sb-host`, microVM kernel/initramfs SHA-256 digests, and mandatory GitHub owner / AWS account allowlists under **Settings -> Tools -> SecretBridge for 1Password**.

### 4. Completion Gate

```sh
# Offline (default when dependencies are pre-cached):
make check
# Online (fresh CI or developer machine):
SB_ONLINE=1 make check

bash .guard/checks/on-stop
```

## Manual IDE Verification Checklist

1. Open **Settings -> Tools -> SecretBridge for 1Password**, configure `/usr/local/bin/sb-host` + guest kernel/initramfs paths and 64-hex SHA-256 digests, set **Allowed GitHub owners** / **Allowed AWS accounts**, enter an `OP_SERVICE_ACCOUNT_TOKEN`, click **Apply**, and click **Test Enclave & Service Account Capabilities**.
2. Open the **SecretBridge** tool window on the right sidebar and click **Refresh**:
   - Confirm **Create Vault...** is disabled with an explanatory tooltip if the Service Account lacks `can_create_vaults`, and enabled otherwise.
   - Confirm Personal/Private vaults are never exposed or mutated, and `LOGIN` items are excluded/rejected by `SAFE_ITEM_CATEGORIES`.
3. Click **Generate Secret (In-VM)...**, generate a 40-char secret, and verify that `secretbridge.json` receives only the `op://` reference while zero secret plaintext crosses to the host.
4. Click **Capture Secret (15s Armed Copy)...**, wait for the status label to switch from `Preparing enclave & arming capture hook...` to `ARMED (15s remaining)`, copy text in another app within 15 seconds, and verify the status banner reports `Zero-Pasteboard Intercept` (or `1ms Pasteboard Snapshot-Restore Fallback`) and restores prior clipboard contents immediately.
5. Configure explicit `github` and/or `aws` targets in `secretbridge.json`, click **Preview & Sync...**, inspect the HMAC-signed plan diff, click **Apply Signed Plan**, and confirm cloud target updates.
