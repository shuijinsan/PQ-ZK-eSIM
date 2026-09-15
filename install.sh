#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
EUICC="$ROOT/artifact/terminal/euicc"
AARCH64_DEPS="$EUICC/libs/aarch64"    # AArch64 prebuilt-library destination
DEPS_DIR="$ROOT/.deps"                # source and temporary build directory (gitignored)
OPENSSL_VERSION="3.0.13"
LIBOQS_VERSION="0.15.0"

log()  { echo "== $* =="; }
fail() { echo "❌ $*"; exit 1; }

cd "$ROOT"

# ------------------------------------------------------------------
# ------------------------------------------------------------------
log "Check and install system dependencies"
command -v sudo >/dev/null 2>&1 || fail "sudo is required to install system packages"

PKGS=""
command -v gcc                    >/dev/null 2>&1 || PKGS="$PKGS build-essential"
command -v cmake                  >/dev/null 2>&1 || PKGS="$PKGS cmake"
command -v git                    >/dev/null 2>&1 || PKGS="$PKGS git"
command -v python3                >/dev/null 2>&1 || PKGS="$PKGS python3"
command -v pip3                   >/dev/null 2>&1 || PKGS="$PKGS python3-pip"
command -v aarch64-linux-gnu-gcc  >/dev/null 2>&1 || PKGS="$PKGS gcc-aarch64-linux-gnu"
command -v qemu-aarch64-static    >/dev/null 2>&1 || PKGS="$PKGS qemu-user-static"
command -v wget                   >/dev/null 2>&1 || PKGS="$PKGS wget"
[ -d /usr/include/openssl ]                       || PKGS="$PKGS libssl-dev"
if [ -n "$PKGS" ]; then
  log "Install system packages:$PKGS"
  sudo apt-get update
  sudo apt-get install -y $PKGS
fi

# ------------------------------------------------------------------
# ------------------------------------------------------------------
log "Install Python dependencies (numpy / pandas / matplotlib)"
python3 -m pip install --user numpy pandas matplotlib

# ------------------------------------------------------------------
# ------------------------------------------------------------------
OPENSSL_PREFIX="$AARCH64_DEPS/openssl"
if [ -f "$OPENSSL_PREFIX/lib/libcrypto.a" ]; then
  log "OpenSSL aarch64 already exists; skipping"
else
  log "Build OpenSSL $OPENSSL_VERSION (AArch64 static libraries)"
  mkdir -p "$DEPS_DIR"
  if [ ! -d "$DEPS_DIR/openssl-$OPENSSL_VERSION" ]; then
    ( cd "$DEPS_DIR" \
      && wget "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz" \
      && tar xf "openssl-$OPENSSL_VERSION.tar.gz" )
  fi
  ( cd "$DEPS_DIR/openssl-$OPENSSL_VERSION" \
    && ./Configure linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu- \
         --prefix="$OPENSSL_PREFIX" no-shared \
    && make -j"$(nproc)" \
    && make install_sw )
fi

# ------------------------------------------------------------------
# 4. liboqs (native + aarch64)
# ------------------------------------------------------------------
LIBOQS_SRC="$DEPS_DIR/liboqs"
if [ ! -d "$LIBOQS_SRC" ]; then
  log "Download liboqs $LIBOQS_VERSION"
  mkdir -p "$DEPS_DIR"
  git clone --depth 1 --branch "$LIBOQS_VERSION" \
    https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC"
fi

if [ -f /usr/local/lib/liboqs.so ] || [ -f /usr/local/lib/liboqs.a ]; then
  log "liboqs native already exists; skipping"
else
  log "Build liboqs (native x86)"
  ( cd "$LIBOQS_SRC" \
    && cmake -S . -B build_native -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build build_native -j"$(nproc)" \
    && sudo cmake --install build_native )
fi

LIBOQS_AARCH64_PREFIX="$AARCH64_DEPS/liboqs"
if [ -f "$LIBOQS_AARCH64_PREFIX/lib/liboqs.a" ]; then
  log "liboqs aarch64 already exists; skipping"
else
  log "Build liboqs (AArch64 cross-compile)"
  ( cd "$LIBOQS_SRC" \
    && cmake -S . -B build_aarch64 \
         -DCMAKE_SYSTEM_NAME=Linux \
         -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
         -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
         -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_INSTALL_PREFIX="$LIBOQS_AARCH64_PREFIX" \
         -DOQS_USE_OPENSSL=ON \
         -DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX" \
    && cmake --build build_aarch64 -j"$(nproc)" \
    && cmake --install build_aarch64 )
fi

# ------------------------------------------------------------------
# ------------------------------------------------------------------
log "Build C core"
[ -f "$EUICC/build.sh" ] || fail "Not found $EUICC/build.sh"
( cd "$EUICC" && bash build.sh )

# ------------------------------------------------------------------
# 6. Prepare result directories
# ------------------------------------------------------------------
log "Prepare result directories"
mkdir -p claims/claim1_qemu_performance/results \
         claims/claim3_dos_early_reject/results \
         claims/claim4_sliding_window/results \
         claims/claim5_sparse_noise/results

log "Installation complete"
echo "  Run demo : bash artifact/demo/run.sh"
echo "  Run claims : bash claims/<claim>/run.sh [--quick|--full]"
echo "  Validate results : bash validate.sh"
