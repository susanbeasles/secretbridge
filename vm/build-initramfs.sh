#!/usr/bin/env bash
set -euo pipefail

# Reproducible minimal glibc Linux microVM initramfs builder for SecretBridge.
# Stages strictly under ./vm/out/ (gitignored) -- never touches /tmp or cache dirs.
#
# Required inputs:
#   SB_ENCLAVE_BIN         Path to compiled Linux sb-enclave binary
#   SB_OP_CORE_SO          Path to libop_uniffi_core.so (glibc-linked)
#   SB_OP_CORE_SHA256      Expected 64-char lowercase hex SHA-256 of libop_uniffi_core.so

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${REPO_ROOT}/vm/out"
STAGE_DIR="${OUT_DIR}/rootfs-stage"

ENCLAVE_BIN="${SB_ENCLAVE_BIN:-${REPO_ROOT}/target/release/sb-enclave}"
OP_CORE_SO="${SB_OP_CORE_SO:-}"
OP_CORE_SHA256="${SB_OP_CORE_SHA256:-}"
VSOCK_PORT="${SB_VSOCK_PORT:-5190}"

if [[ ! -f "${ENCLAVE_BIN}" ]]; then
  echo "error: sb-enclave binary not found at ${ENCLAVE_BIN}" >&2
  exit 1
fi

if [[ -z "${OP_CORE_SO}" || ! -f "${OP_CORE_SO}" ]]; then
  echo "error: set SB_OP_CORE_SO to a valid libop_uniffi_core.so file" >&2
  exit 1
fi

if [[ ! "${OP_CORE_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "error: set SB_OP_CORE_SHA256 to the 64-char lowercase hex SHA-256 of libop_uniffi_core.so" >&2
  exit 1
fi

ACTUAL_SO_SHA256="$(sha256sum "${OP_CORE_SO}" | awk '{print $1}')"
if [[ "${ACTUAL_SO_SHA256}" != "${OP_CORE_SHA256}" ]]; then
  echo "error: libop_uniffi_core.so SHA-256 mismatch (expected ${OP_CORE_SHA256}, got ${ACTUAL_SO_SHA256})" >&2
  exit 1
fi

rm -rf "${STAGE_DIR}"
mkdir -p \
  "${STAGE_DIR}/bin" \
  "${STAGE_DIR}/dev" \
  "${STAGE_DIR}/etc/ssl/certs" \
  "${STAGE_DIR}/lib" \
  "${STAGE_DIR}/lib64" \
  "${STAGE_DIR}/proc" \
  "${STAGE_DIR}/sys" \
  "${STAGE_DIR}/usr/lib"

install -m 0755 "${ENCLAVE_BIN}" "${STAGE_DIR}/bin/sb-enclave"
install -m 0444 "${OP_CORE_SO}" "${STAGE_DIR}/usr/lib/libop_uniffi_core.so"

if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  install -m 0444 /etc/ssl/certs/ca-certificates.crt "${STAGE_DIR}/etc/ssl/certs/ca-certificates.crt"
fi

# Copy minimal glibc dynamic linker and shared library dependencies required by sb-enclave and libop_uniffi_core.so
copy_elf_deps() {
  local bin="$1"
  ldd "${bin}" | awk '{
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^\//) print $i
    }
  }' | sort -u | while IFS= read -r lib_path; do
    if [[ -f "${lib_path}" ]]; then
      local dest_dir
      dest_dir="${STAGE_DIR}$(dirname "${lib_path}")"
      mkdir -p "${dest_dir}"
      cp -L "${lib_path}" "${dest_dir}/$(basename "${lib_path}")"
      chmod 0555 "${dest_dir}/$(basename "${lib_path}")"
    fi
  done
}

copy_elf_deps "${ENCLAVE_BIN}"
copy_elf_deps "${OP_CORE_SO}"

cat > "${STAGE_DIR}/init" <<EOF
#!/bin/sb-enclave-init-disabled
EOF

# If busybox is installed on the build host, include minimal mount/ip applet for /init bootstrap;
# otherwise /bin/sb-enclave runs directly when kernel mounts devtmpfs.
if command -v busybox >/dev/null 2>&1; then
  install -m 0755 "$(command -v busybox)" "${STAGE_DIR}/bin/busybox"
  copy_elf_deps "$(command -v busybox)"
  cat > "${STAGE_DIR}/init" <<EOF
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox ip link set lo up || true
/bin/busybox ip link set eth0 up || true
/bin/busybox udhcpc -i eth0 -n -q || true
exec /bin/sb-enclave --vsock-port ${VSOCK_PORT} --op-core-lib /usr/lib/libop_uniffi_core.so --op-core-sha256 ${OP_CORE_SHA256}
EOF
else
  ln -sf /bin/sb-enclave "${STAGE_DIR}/init"
fi
chmod 0755 "${STAGE_DIR}/init"

# Normalize mtimes for reproducible cpio archive generation
find "${STAGE_DIR}" -maxdepth 2 -exec touch -h -d "@0" {} +
mkdir -p "${OUT_DIR}"
(
  cd "${STAGE_DIR}"
  find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --owner=0:0 --quiet | gzip -n -9 > "${OUT_DIR}/initramfs.cpio.gz"
)
chmod 0600 "${OUT_DIR}/initramfs.cpio.gz"
sha256sum "${OUT_DIR}/initramfs.cpio.gz" | awk '{print $1}' > "${OUT_DIR}/initramfs.sha256"
echo "Built ${OUT_DIR}/initramfs.cpio.gz (SHA-256: $(cat "${OUT_DIR}/initramfs.sha256"))"
