#!/usr/bin/env bash
set -euo pipefail

# Reproducible minimal glibc Linux microVM initramfs builder for SecretBridge.
# Stages strictly under ./vm/out/ (gitignored) -- never touches /tmp or cache dirs.
#
# Inputs (supports both SB_* and Makefile OP_UNIFFI_* variable names):
#   SB_OP_CORE_SO / OP_UNIFFI_LIB          Path to libop_uniffi_core.so (glibc-linked)
#   SB_OP_CORE_SHA256 / OP_UNIFFI_SHA256   Expected 64-char lowercase hex SHA-256 of libop_uniffi_core.so
#   SB_ENCLAVE_BIN                         Optional path to prebuilt Linux sb-enclave release binary
#   SB_BUILD_ENCLAVE                       Set to 1 to compile sb-enclave with SB_PINNED_OP_CORE_SHA256

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${REPO_ROOT}/vm/out"
STAGE_DIR="${OUT_DIR}/rootfs-stage"

ENCLAVE_BIN="${SB_ENCLAVE_BIN:-${REPO_ROOT}/target/release/sb-enclave}"
OP_CORE_SO="${SB_OP_CORE_SO:-${OP_UNIFFI_LIB:-}}"
OP_CORE_SHA256="${SB_OP_CORE_SHA256:-${OP_UNIFFI_SHA256:-}}"
BUILD_ENCLAVE="${SB_BUILD_ENCLAVE:-0}"

if [[ -z "${OP_CORE_SO}" || ! -f "${OP_CORE_SO}" ]]; then
  echo "error: set SB_OP_CORE_SO (or OP_UNIFFI_LIB) to a valid libop_uniffi_core.so file" >&2
  exit 1
fi

if [[ ! "${OP_CORE_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "error: set SB_OP_CORE_SHA256 (or OP_UNIFFI_SHA256) to the 64-char lowercase hex SHA-256 of libop_uniffi_core.so" >&2
  exit 1
fi

ACTUAL_SO_SHA256="$(sha256sum "${OP_CORE_SO}" | awk '{print $1}')"
if [[ "${ACTUAL_SO_SHA256}" != "${OP_CORE_SHA256}" ]]; then
  echo "error: libop_uniffi_core.so SHA-256 mismatch (expected ${OP_CORE_SHA256}, got ${ACTUAL_SO_SHA256})" >&2
  exit 1
fi

if [[ "${BUILD_ENCLAVE}" == "1" || ! -f "${ENCLAVE_BIN}" ]]; then
  CARGO_EXTRA_FLAGS=()
  if [[ "${SB_CARGO_OFFLINE:-0}" == "1" ]]; then
    CARGO_EXTRA_FLAGS+=(--offline)
  fi
  echo "Compiling sb-enclave (--release --locked) with SB_PINNED_OP_CORE_SHA256=${OP_CORE_SHA256}..."
  (
    cd "${REPO_ROOT}"
    SB_PINNED_OP_CORE_SHA256="${OP_CORE_SHA256}" \
      cargo build --release --locked -p sb-enclave "${CARGO_EXTRA_FLAGS[@]}"
  )
fi

if [[ ! -f "${ENCLAVE_BIN}" ]]; then
  echo "error: sb-enclave binary not found at ${ENCLAVE_BIN}" >&2
  exit 1
fi

if ! command -v readelf >/dev/null 2>&1; then
  echo "error: readelf (binutils) is required to inspect ELF dependencies safely without ldd" >&2
  exit 1
fi

elf_machine() {
  readelf -h "$1" 2>/dev/null | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p' | head -n 1
}

TARGET_MACHINE="$(elf_machine "${ENCLAVE_BIN}")"
SO_MACHINE="$(elf_machine "${OP_CORE_SO}")"
if [[ -z "${TARGET_MACHINE}" || "${TARGET_MACHINE}" != "${SO_MACHINE}" ]]; then
  echo "error: ELF architecture mismatch between sb-enclave (${TARGET_MACHINE:-unknown}) and libop_uniffi_core.so (${SO_MACHINE:-unknown})" >&2
  exit 1
fi

# Verify that `sb-enclave` was compiled with `SB_PINNED_OP_CORE_SHA256` matching `OP_CORE_SHA256` (`V2-H2`)
if ! LC_ALL=C grep -a -F -q "${OP_CORE_SHA256}" "${ENCLAVE_BIN}"; then
  echo "error: ${ENCLAVE_BIN} does not embed SB_PINNED_OP_CORE_SHA256=${OP_CORE_SHA256}; rebuild with SB_BUILD_ENCLAVE=1 or SB_PINNED_OP_CORE_SHA256=${OP_CORE_SHA256}" >&2
  exit 1
fi

case "${TARGET_MACHINE}" in
  *AArch64*)
    LIB_SEARCH_DIRS=(
      /lib/aarch64-linux-gnu
      /usr/lib/aarch64-linux-gnu
      /lib64
      /usr/lib64
      /lib
      /usr/lib
    )
    ;;
  *X86-64*)
    LIB_SEARCH_DIRS=(
      /lib/x86_64-linux-gnu
      /usr/lib/x86_64-linux-gnu
      /lib64
      /usr/lib64
      /lib
      /usr/lib
    )
    ;;
  *)
    LIB_SEARCH_DIRS=(
      /lib64
      /usr/lib64
      /lib
      /usr/lib
    )
    ;;
esac

find_host_shlib() {
  local soname="$1"
  local dir candidate cand_machine
  for dir in "${LIB_SEARCH_DIRS[@]}"; do
    candidate="${dir}/${soname}"
    if [[ -f "${candidate}" ]]; then
      cand_machine="$(elf_machine "${candidate}")"
      if [[ "${cand_machine}" == "${TARGET_MACHINE}" ]]; then
        printf '%s\n' "${candidate}"
        return 0
      fi
    fi
  done
  return 1
}

stage_host_file() {
  local host_path="$1"
  local mode="$2"
  local dest="${STAGE_DIR}${host_path}"
  if [[ -e "${dest}" || -L "${dest}" ]]; then
    chmod u+w "${dest}" 2>/dev/null || true
    rm -f "${dest}"
  fi
  mkdir -p "$(dirname "${dest}")"
  cp -L "${host_path}" "${dest}"
  chmod "${mode}" "${dest}"
}

# Safely resolves ELF PT_INTERP and transitive DT_NEEDED shared libraries via `readelf`
# (never invoking `ldd` / dynamic linker execution on binary artifacts, closing H7).
declare -A VISITED_ELFS=()
resolve_elf_tree() {
  local elf_path="$1"
  if [[ -n "${VISITED_ELFS[${elf_path}]:-}" ]]; then
    return 0
  fi
  VISITED_ELFS["${elf_path}"]=1

  local interp
  interp="$(readelf -lW "${elf_path}" 2>/dev/null | sed -n 's/.*\[Requesting program interpreter: \(.*\)\].*/\1/p' | head -n 1)"
  if [[ -n "${interp}" && -f "${interp}" ]]; then
    stage_host_file "${interp}" 0555
  fi

  local soname resolved
  while IFS= read -r soname; do
    [[ -z "${soname}" ]] && continue
    if [[ "${soname}" == "libop_uniffi_core.so" ]]; then
      continue
    fi
    if resolved="$(find_host_shlib "${soname}")"; then
      if [[ -z "${VISITED_ELFS[${resolved}]:-}" ]]; then
        stage_host_file "${resolved}" 0555
        resolve_elf_tree "${resolved}"
      fi
    else
      echo "error: required glibc shared library '${soname}' (${TARGET_MACHINE}, needed by ${elf_path}) not found in standard library paths" >&2
      exit 1
    fi
  done < <(readelf -dW "${elf_path}" 2>/dev/null | sed -n 's/.*(NEEDED).*Shared library: \[\(.*\)\].*/\1/p')
}

rm -rf "${STAGE_DIR}"
cleanup_stage() {
  chmod -R u+w "${STAGE_DIR}" 2>/dev/null || true
  rm -rf "${STAGE_DIR}"
}
trap cleanup_stage EXIT

mkdir -p \
  "${STAGE_DIR}/bin" \
  "${STAGE_DIR}/dev" \
  "${STAGE_DIR}/etc/ssl/certs" \
  "${STAGE_DIR}/lib" \
  "${STAGE_DIR}/lib64" \
  "${STAGE_DIR}/proc" \
  "${STAGE_DIR}/sys" \
  "${STAGE_DIR}/usr/lib" \
  "${OUT_DIR}"

# Install self-contained PID-1 Rust enclave binary directly as /init (no busybox/shell and ZERO private keys in initramfs, V2-C1)
install -m 0755 "${ENCLAVE_BIN}" "${STAGE_DIR}/init"
ln -s /init "${STAGE_DIR}/bin/sb-enclave"
install -m 0444 "${OP_CORE_SO}" "${STAGE_DIR}/usr/lib/libop_uniffi_core.so"

resolve_elf_tree "${ENCLAVE_BIN}"
resolve_elf_tree "${OP_CORE_SO}"

# Explicitly include glibc NSS DNS/files modules loaded dynamically via dlopen() for getaddrinfo()
for nss_lib in libnss_files.so.2 libnss_dns.so.2 libresolv.so.2; do
  if nss_path="$(find_host_shlib "${nss_lib}")"; then
    stage_host_file "${nss_path}" 0555
    resolve_elf_tree "${nss_path}"
  fi
done

cat > "${STAGE_DIR}/etc/nsswitch.conf" <<'EOF'
hosts: files dns
EOF
chmod 0444 "${STAGE_DIR}/etc/nsswitch.conf"

if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  install -m 0444 /etc/ssl/certs/ca-certificates.crt "${STAGE_DIR}/etc/ssl/certs/ca-certificates.crt"
fi

# Normalize mtimes across all staged tree depths for deterministic cpio archive generation (H7)
find "${STAGE_DIR}" -exec touch -h -d "@0" {} +
(
  cd "${STAGE_DIR}"
  if cpio --help 2>&1 | grep -q -- '--reproducible'; then
    find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --owner=0:0 --reproducible --quiet | gzip -n -9 > "${OUT_DIR}/initramfs.cpio.gz"
  else
    find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --owner=0:0 --quiet | gzip -n -9 > "${OUT_DIR}/initramfs.cpio.gz"
  fi
)
chmod 0600 "${OUT_DIR}/initramfs.cpio.gz"
sha256sum "${OUT_DIR}/initramfs.cpio.gz" | awk '{print $1}' > "${OUT_DIR}/initramfs.sha256"
echo "Built ${OUT_DIR}/initramfs.cpio.gz (SHA-256: $(cat "${OUT_DIR}/initramfs.sha256"), zero embedded private keys)"
